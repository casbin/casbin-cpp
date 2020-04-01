#include "model.h"

auto get_key_suffix(const int i) -> string
{
	if (i == 1) {
		return "";
	}

	return to_string(i);
}

auto Model::load_assertion(Config c, const string& sec, const string& key) -> bool
{
	const auto value = c.get(sectionNameMap.find(sec)->second + "::" + key);
	return add_def(sec, key, value);
}

auto Model::add_def(const string& sec, const string& key, const string& value) -> bool
{
	if (value.empty()) return false;
	auto ast = new assertion();
	ast->key = key;
	ast->value = value;

	// Stores tokens in assertion such as r_sub, p_sub
	if (sec == "r" || sec == "p") {
		ast->tokens = split(ast->value, ',');
		for (auto itr = ast->tokens.begin(); itr != ast->tokens.end(); ++itr) {
			*itr = trim(*itr);
			*itr = key + "_" + *itr;
		}
	}
	else {
		ast->value = escape_assertion(value); // Replaces r.sub in matcher to p_sub
	}

	if (model.find(sec) == model.end()) {
		auto temp = new AssertionMap(key, ast);
		model.insert(make_pair(sec, temp));
	}

	return true;
}

void Model::load_model(const string& file_path) {
	const auto cfg = Config(file_path);
	load_model_from_config(cfg);
}

auto Model::load_model_from_config(const Config& cfg) -> void
{
	for (auto& section_name : sectionNameMap) {
		load_section(cfg, section_name.first);
	}

	vector<string> ms;
	for (const auto& rs : required_sections_) {
		if (!has_section(rs)) ms.push_back(sectionNameMap.find(rs)->second);
	}
	if (!ms.empty()) printf("Missing sections are: %s \n", join(ms, ',').c_str());
}

auto Model::load_section(const Config& cfg, const string& sec) -> void
{
	auto i = 1;
	while (true) {
		if (!load_assertion(cfg, sec, sec + get_key_suffix(i))) break;
		else i++;
	}
}

auto Model::has_section(const string& sec) -> bool
{
	return model.find(sec) != model.end();
}

void Model::print_model() {
	for (auto& item : model) {
		for (auto& assertion : item.second->data) {
			printf("%s.%s: %s \n", item.first.c_str(), assertion.first.c_str(), assertion.second->value.c_str());
		}
	}
}

auto Model::clear_policy() -> void
{
	auto temp = model.find("p")->second;
	for (auto itr = temp->data.begin(); itr != temp->data.end(); ++itr) {
		auto ast = itr->second;
		ast->policy.clear();
	}

	auto temp1 = model.find("g")->second;
	for (auto itr1 = temp1->data.begin(); itr1 != temp1->data.end(); ++itr1) {
		auto ast = itr1->second;
		ast->policy.clear();
	}
}

auto Model::build_role_links(role_manager* rm) -> void
{
	if (model.find("g") != model.end()) {
		auto astm = model.find("g")->second;
		for (auto itr = astm->data.begin(); itr != astm->data.end(); ++itr) {
			auto ast = itr->second;
			ast->build_role_links(rm);
		}
	}
}

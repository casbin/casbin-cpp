#include "adapter.h"

auto Adapter::load_policy_line(string line, Model* model) const -> void
{
	if (line.empty() || *line.begin() == '#') {
		return;
	}

	auto tokens = split(line, ',');
	for (auto itr = tokens.begin(); itr != tokens.end(); ++itr) {
		*itr = trim(*itr);
	}

	const auto result = vector(tokens.begin() + 1, tokens.end());
	const auto key = tokens[0];
	const auto sec = key.substr(0, 1);
	auto tempasm = model->model.find(sec)->second;
	auto tempas = tempasm->data.find(key)->second;
	tempas->policy.push_back(result);
}

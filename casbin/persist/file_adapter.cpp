#include "file_adapter.h"

file_adapter::file_adapter(const string& path)
{
	file_path_ = path;
}

void file_adapter::load_policy(Model* model) {
	if (file_path_.empty()) return;
	
	ifstream file(file_path_, ios::out);
	if (!file.is_open())
	{
		cerr << "Error: Unable to open policy file " << file_path_ << " for reading!" << endl;
		return;
	}

	string line;
	while (getline(file, line))
	{
		line = trim(line);
		load_policy_line(line, model);
	}

	file.close();
}

void file_adapter::save_policy(Model* model) {
	if (file_path_.empty()) return;

	string buffer = "";

	auto astm = model->model.find("p")->second;
	for (auto itr = astm->data.begin(); itr != astm->data.end(); ++itr) {
		for (const auto& arr : itr->second->policy) {
			buffer += itr->first + ", ";
			buffer += join(arr, ',');
			buffer += '\n';
		}
	}

	astm = model->model.find("g")->second;
	for (auto itr = astm->data.begin(); itr != astm->data.end(); ++itr) {
		for (const auto& arr : itr->second->policy) {
			buffer += itr->first + ", ";
			buffer += join(arr, ',');
			buffer += '\n';
		}
	}

	ofstream fout;
	fout.open(file_path_);

	while (fout) {
		fout << buffer;
	}

	fout.close();
}

void file_adapter::add_policy(string sec, string ptype, vector<string> rule) {
	return;
}

void file_adapter::remove_policy(string sec, string ptype, vector<string> rule) {
	return;
}
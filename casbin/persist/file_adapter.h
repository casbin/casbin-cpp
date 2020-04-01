#pragma once

#include <iostream>
#include <fstream>
#include "adapter.h"

using namespace std;

class file_adapter final : public Adapter {
	string file_path_;
public:
	explicit file_adapter(const string& path);
	auto load_policy(Model*) -> void override;
	auto save_policy(Model*) -> void override;
	auto add_policy(string, string, vector<string>) -> void override;
	auto remove_policy(string, string, vector<string>) -> void override;
};
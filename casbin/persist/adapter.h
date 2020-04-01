#pragma once
#include <vector>
#include "../util/utils.h"
#include "../model/model.h"

using namespace std;

class Adapter {
public:
	virtual ~Adapter() = default;
	virtual void load_policy(Model*)= 0;
	virtual void save_policy(Model*) = 0;
	virtual void add_policy(string, string, vector<string>) = 0;
	virtual void remove_policy(string, string, vector<string>) = 0;
	void load_policy_line(string, Model*) const;
};
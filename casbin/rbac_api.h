#ifndef CASBIN_CPP_RBAC_API
#define CASBIN_CPP_RBAC_API

#include "./enforcer.h"
#include "./util/joinSlice.h"
#include "./util/setSubtract.h"

// GetRolesForUser gets the roles that a user has.
vector<string> Enforcer :: GetRolesForUser(string name) {
    vector<string> domain;
	vector<string> res = this->model.M["g"].AMap["g"]->RM->GetRoles(name, domain);
	return res;
}

// GetUsersForRole gets the users that has a role.
vector<string> Enforcer :: GetUsersForRole(string name) {
	vector<string> domain;
	vector<string> res = this->model.M["g"].AMap["g"]->RM->GetUsers(name, domain);
	return res;
}

// HasRoleForUser determines whether a user has a role.
bool Enforcer :: HasRoleForUser(string name, string role) {
	vector<string> roles = this->GetRolesForUser(name);

	bool hasRole = false;
    for(int i = 0 ; i < roles.size() ; i++){
        if(roles[i] == role){
            hasRole = true;
            break;
        }
    }

	return hasRole;
}

// AddRoleForUser adds a role for a user.
// Returns false if the user already has the role (aka not affected).
bool Enforcer :: AddRoleForUser(string user, string role) {
    vector<string> params{user, role};
	return this->AddGroupingPolicy(params);
}

// DeleteRoleForUser deletes a role for a user.
// Returns false if the user does not have the role (aka not affected).
bool Enforcer :: DeleteRoleForUser(string user, string role) {
    vector<string> params{user, role};
	return this->RemoveGroupingPolicy(params);
}

// DeleteRolesForUser deletes all roles for a user.
// Returns false if the user does not have any roles (aka not affected).
bool Enforcer :: DeleteRolesForUser(string user) {
    vector<string> fieldValues{user};
	return this->RemoveFilteredGroupingPolicy(0, fieldValues);
}

// DeleteUser deletes a user.
// Returns false if the user does not exist (aka not affected).
bool Enforcer :: DeleteUser(string user) {
    vector<string> fieldValues{user};

	bool res1 = this->RemoveFilteredGroupingPolicy(0, fieldValues);

	bool res2 = this->RemoveFilteredPolicy(0, fieldValues);

	return res1 || res2;
}

// DeleteRole deletes a role.
// Returns false if the role does not exist (aka not affected).
bool Enforcer :: DeleteRole(string role) {
    vector<string> fieldValues{role};

	bool res1 = this->RemoveFilteredGroupingPolicy(1, fieldValues);

	bool res2 = this->RemoveFilteredPolicy(0, fieldValues);

	return res1 || res2;
}

// DeletePermission deletes a permission.
// Returns false if the permission does not exist (aka not affected).
bool Enforcer :: DeletePermission(vector<string> permission) {
    vector<string> fieldValues{permission};
	return this->RemoveFilteredPolicy(1, fieldValues);
}

// AddPermissionForUser adds a permission for a user or role.
// Returns false if the user or role already has the permission (aka not affected).
bool Enforcer :: AddPermissionForUser(string user, vector<string> permission) {
	return this->AddPolicy(joinSlice(user, permission));
}

// DeletePermissionForUser deletes a permission for a user or role.
// Returns false if the user or role does not have the permission (aka not affected).
bool Enforcer :: DeletePermissionForUser(string user, vector<string> permission) {
	return this->RemovePolicy(joinSlice(user, permission));
}

// DeletePermissionsForUser deletes permissions for a user or role.
// Returns false if the user or role does not have any permissions (aka not affected).
bool Enforcer :: DeletePermissionsForUser(string user) {
    vector<string> fieldValues{user};
	return this->RemoveFilteredPolicy(0, fieldValues);
}

// GetPermissionsForUser gets permissions for a user or role.
vector<vector<string>> Enforcer :: GetPermissionsForUser(string user) {
    vector<string> fieldValues{user};
	return this->GetFilteredPolicy(0, fieldValues);
}

// HasPermissionForUser determines whether a user has a permission.
bool Enforcer :: HasPermissionForUser(string user, vector<string> permission) {
	return this->HasPolicy(joinSlice(user, permission));
}

// GetImplicitRolesForUser gets implicit roles that a user has.
// Compared to GetRolesForUser(), this function retrieves indirect roles besides direct roles.
// For example:
// g, alice, role:admin
// g, role:admin, role:user
//
// GetRolesForUser("alice") can only get: ["role:admin"].
// But GetImplicitRolesForUser("alice") will get: ["role:admin", "role:user"].
vector<string> Enforcer :: GetImplicitRolesForUser(string name, vector<string> domain) {
	vector<string> res;
	unordered_map <string, bool> roleSet;
	roleSet[name] = true;

	vector<string> q;
	q.push_back(name);

	while(q.size() > 0) {
		string name = q[0];
		q.erase(q.begin());

		vector<string> roles = this->rm->GetRoles(name, domain);

		for(int i = 0 ; i < roles.size() ; i++){
			if(!(roleSet.find(roles[i]) != roleSet.end())){
				res.push_back(roles[i]);
				q.push_back(roles[i]);
				roleSet[roles[i]] = true;
			}
		}
	}

	return res;
}

// GetImplicitPermissionsForUser gets implicit permissions for a user or role.
// Compared to GetPermissionsForUser(), this function retrieves permissions for inherited roles.
// For example:
// p, admin, data1, read
// p, alice, data2, read
// g, alice, admin
//
// GetPermissionsForUser("alice") can only get: [["alice", "data2", "read"]].
// But GetImplicitPermissionsForUser("alice") will get: [["admin", "data1", "read"], ["alice", "data2", "read"]].
vector<vector<string>> Enforcer :: GetImplicitPermissionsForUser(string user, vector<string> domain) {
	vector<string> roles = this->GetImplicitRolesForUser(user, domain);
	roles.insert(roles.begin(), user);

	bool withDomain = false;
	if(domain.size() == 1) {
		withDomain = true;
	} else if(domain.size() > 1) {
		throw CasbinEnforcerException("Domain should be 1 parameter");
	}

	vector<vector<string>> res;
	vector<vector<string>> permissions;
	
	for(int i = 0 ; i < roles.size() ; i++) {
		if(withDomain)
			permissions = this->GetPermissionsForUserInDomain(roles[i], domain[0]);
		else
			permissions = this->GetPermissionsForUser(roles[i]);

		for(int i = 0 ; i < permissions.size() ; i++)
			res.push_back(permissions[i]);
	}

	return res;
}

// GetImplicitUsersForPermission gets implicit users for a permission.
// For example:
// p, admin, data1, read
// p, bob, data1, read
// g, alice, admin
//
// GetImplicitUsersForPermission("data1", "read") will get: ["alice", "bob"].
// Note: only users will be returned, roles (2nd arg in "g") will be excluded.
vector<string> Enforcer :: GetImplicitUsersForPermission(vector<string> permission) {
	// vector<string> subjects = this->GetAllSubjects();
	// vector<string> roles = this->GetAllRoles();

	// vector<string> users = setSubtract(subjects, roles);

	// vector<string> res;
	// for(int i = 0 ; i < users.size() ; i++) {
	// 	vector<string> req = joinSlice(users[i], permission);
		
	// 	// vector<void *> newReq;
	// 	for(int i = 0 ; i < req.size() ; i++)
	// 		newReq.push_back((void *)(&req[i]));
	// 	bool allowed = this->Enforce(newReq);

	// 	if(allowed)
	// 		res.push_back(users[i]);
	// }

	// return res;
}

#endif
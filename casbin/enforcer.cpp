/*
* Copyright 2020 The casbin Authors. All Rights Reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#include "pch.h"
#include "enforcer.h"

bool Enforcer::enforce(string sub, string obj, string act) {
	return false;
}

// For knowing the type of variables with two arguments
template<typename R,typename T>
string typeInfo(R n, T args) {
    string S={};
    S = S+ typeid(n).name()[0] + typeid(args).name()[0];
    return S;
}

// For knowing the type of variables with one argument
template<typename R>
char typeInfo(R n) {
    return typeid(n).name()[0];
}
// NewEnforcer creates an enforcer via file or DB.
//
// File:
//	string error;
//	Enforcer e;
// 	tie(e, error)= casbin.NewEnforcer("path/to/basic_model.conf", "path/to/basic_policy.csv");
//
// MySQL DB:
//
// 	a := mysqladapter.NewDBAdapter("mysql", "mysql_username:mysql_password@tcp(127.0.0.1:3306)/");
// 	string error;
//  Enforcer e;
//  tie(e, error)= casbin.NewEnforcer("path/to/basic_model.conf", a);
//
template<typename R,typename ... T>
tuple <Enforcer, string> newEnforcer(R modelPath, T ... Q ){
    int p = sizeof...(Q);
    string params = {};
    Enforcer e1;
	Enforcer *e;
	e = &e1;

    // Knowing the type of variables and storing it in string.
    if (p > 0) {
        params = params + typeid(modelPath).name()[0] + typeInfo(Q ...);
    }
    else {
        params = params + typeid(modelPath).name()[0];    
    }

    int paramLen = params.size();
    int parsedParamLen = 0;

    if (paramLen >= 1) {
        if(params[paramLen-1] == 'b')
		{
		    // e->EnableLog(enableLog);

			parsedParamLen++;
		}
	}

    if( paramLen-parsedParamLen == 2) {
        char p0 = params[0];
        switch(p0) {
        case 'P': {
            char p1 = params[1];
            switch(p1) {
            case 'P': {
                // auto err = e->InitWithFile(p0, p1);
                // if(err != NULL) {
                //    return make_tuple(Enforcer(), err);
            }
            default: {
                // auto err = e->InitWithAdapter(p0, p1.(persist.Adaptor));
                // if(err != NULL) {
                //    return make_tuple(Enforcer(), err);
            }
            }
        }    
        default:
            switch(params[1]){
            case 'P':
                // return make_tuple(Enforcer(), error.New("Invalid parameters for enforcer"));
            default:{
                // auto err = e->InitWithModelAndAdapter(p0.(model.Model), params[1].(persist.Adapter));
		        // if err != NULL {
			    //     return make_tuple(Enforcer(), err);
		        // }
            }          
            }
        }
    } else if(paramLen-parsedParamLen == 1) {
		char p0 = params[0];
        switch(p0){ 
		case 'P': {
			// auto err = e->InitWithFile(p0, "");
			// if err != NULL {
			//	return make_tuple(Enforcer(), err);
			// }
        }
		default: {
			// auto err = e->InitWithModelAndAdapter(p0.(model.Model), nil);
			// if err != NULL {
			// 	return make_tuple(Enforcer(), err);
		    //}
        }
        }
	} else if (paramLen-parsedParamLen == 0) {
		// return e, " ";
	} else {
		// return make_tuple(Enforcer(), errors.New("invalid parameters for enforcer"));
	}

	return e, "";
}
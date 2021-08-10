#  Copyright 2021 The casbin Authors. All Rights Reserved.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import pycasbin as casbin
from config_path import *
import unittest

class TestModel(unittest.TestCase):

    # def setUp(self):
        # self.basic_config = casbin.Config.NewConfig(basic_model_path)

    def test_NewModel(self):
        model = casbin.Model.NewModel()
        self.assertIsNotNone(model)

    def test_NewModelFromFile(self):
        model = casbin.Model.NewModelFromFile(basic_model_path)
        self.assertIsNotNone(model)

    def test_NewModelFromString(self):
        model_string = """[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act"""
        model = casbin.Model.NewModelFromString(model_string)
        self.assertIsNotNone(model)

    def test_LoadModelFromConfig(self):
        basic_config = casbin.Config.NewConfig(basic_model_path)
        model = casbin.Model.NewModel()
        model.LoadModelFromConfig(basic_config)
        # model = casbin.Model.NewModel()
        # config = casbin.Config.NewConfigFromText("")
        # model.LoadModelFromConfig(config)

    def test_HasSection(self):
        # config = casbin.Config.NewConfig(basic_model_path)
        # model = casbin.Model.NewModel()
        # casbin.LoadModelFromConfig(model, basic_config)

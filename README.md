# casbin-cpp

I implemented the the Enforcer,Model,Adapter,File-Adapter first. <br>
It is a rough version because I start it too late and I want to realize a minimal working demo quickly. <br>
It doesn't has a good coding style because I am in hurry to realize a minimal demo and hesitate about some trade-off. <br>
I will correct the coding style from tomorrow.If you have some advice of coding style and implementation you can point it out.I will correct it soon. <br>

# Instrution
The demo is in the dictory"CasbinTest",and the main function is in the Test.cpp <br>

# Supporting：
1.Using the AddDef to set the Model<br>
2.Using the FileAdapter(filepath) to load the Policy by file<br>
3.Using the adapter.Addpolicy to add policy into the file<br>
4.Using the model.Addpolicy to add policy into the model<br>
5.Using the enforcer to caculate the expression.<br>
6.Some other functions...<br>

# Not Supporting now (to implement soon):
1.Some small function for managing policy<br>
2.functionmap<br>
3.RBAC <br>
4.keymatcher<br>
5.Config (for Loading model)<br>
6.Log<br>

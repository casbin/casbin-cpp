# casbin-cpp

I implemented the the Enforcer,Model,Adapter,File-Adapter first.
It is a rough version because I start it too late and I want to realize a minimal working demo quickly.
It doesn't has a good coding style because I am in hurry to realize a minimal demo and hesitate about some trade-off.
I will correct the coding style from tomorrow.If you have some advice of coding style and implementation you can point it out.I will correct it soon.

# Supporting：
1.Using the AddDef to set the Model
2.Using the FileAdapter(filepath) to load the Policy by file
3.Using the adapter.Addpolicy to add policy into the file
4.Using the model.Addpolicy to add policy into the model
5.Using the enforcer to caculate the expression.
6.Some other functions...

# Not Supporting now (to implement soon):
1.Some small function for managing policy
2.functionmap
3.RBAC 
4.keymatcher
5.Config (for Loading model)
6.Log

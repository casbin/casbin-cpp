## Language Bindings for Casbin

Casbin-CPP provides language bindings to compound the advantages of different languages and to make 
authorization easier and faster.

At present, casbin-cpp provides language bindings for Python.

## Python Bindings

### Installing the PyCasbin module

It is assumed you have CMake >=v3.19 and Python >= 3.2 installed.

1. Clone/download the project:
    ```bash
    git clone https://github.com/casbin/casbin-cpp.git
    ```

2. Make a build directory and generate project files through CMake:
    ```bash
    mkdir build
    cd build
    cmake ..
    ```
    **Note:** Kindly look at the log message to find the directory you need to add in your `sys.path` (Step 5). The log may look like this:
    ```bash
    [pycasbin]: Build "pycasbin" target for Python Bindings
    [pycasbin]: Add "lib/python3.9/site-packages" to your sys.path/USER_SITE variable if not already present
    ```

3. Build the python bindings (`pycasbin` target):
    ```bash
    cmake --build . --config Release --target pycasbin
    ```

4. Install the `pycasbin` module:
    ```bash
    cmake --build . --config Release --target install
    ```
    This will install the module to: 
    - `<prefix>/lib/site-packages` on Windows.
    - `<prefix>/lib/python3.x/site-packages` on UNIX.

    **Note:** The actual install path can be deduced in the log output of Step 2.

5. Add the correct `site-packages` directory path to `sys.path` or `USER_SITE` of your current python configuration if not already present.

Now, you're ready to go!

### Usage

It is assumed that you have `pycasbin` module correctly installed on your system.

First, we import the pycasbin module to a python source file:

```python
import pycasbin as casbin
```

Suppose we want a function to check authorization of a request:

```python
def isAuthorized(req):
    result = True
    if result:
        print('Authorized')
    else
        print('Not authorized!')
```

Here, the request can be a list or a dictionary in the forms:

```python
req = ['subject1', 'object1', 'action1'] # and so on..

req = {
    "sub": "subject1",
    "obj": "object1",
    "act": "action1"  # ... and so on
}
```

We can Enforce this request (or compute the `result` of this request) through `casbin.Enforce()`. 
For that, we need to create a `casbin.Enforcer`:

```python
e = casbin.Enforcer('path/to/model.conf', 'path/to/policy.csv')
```
Make sure that the paths are relative to the current python source file or an absolute path.

Apart from the regular `Enforcer`, you may also use `CachedEnforcer`
depending on your use case.

Incorporating the `Enforcer` in our example gives us:

```python
def isAuthorized(req):
    result = e.Enforce(req)
    if result:
        print('Authorized')
    else
        print('Not authorized!')
```

Rest of the method's name is on par with casbin-CPP.

#### Summary

This sums up the basic usage of pycasbin module:

```python
import pycasbin as casbin

e = casbin.Enforcer('path/to/model.conf', 'path/to/policy.csv')

def isAuthorized(req):
    result = e.Enforce(req)
    if result:
        print('Authorized')
    else
        print('Not authorized!')

isAuthorized(['subject1', 'object1', 'action1'])
isAuthorized(['subject2', 'object2', 'action2'])
# ... and so on
```

If you've done everything right, you'll see your output
without any errors.

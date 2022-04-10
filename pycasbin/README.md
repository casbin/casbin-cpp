## Language Bindings for `casbin-cpp`

At present, `casbin-cpp` provides language bindings for Python, we named it `pycasbin`.

## Python Bindings

### Use `pip` install the `pycasbin` module

It is assumed you have `CMake >=v3.19` and `Python >= 3.6` installed. Current `pycasbin` only support `pip` install in local machine. 

1. Clone/download the project:
    ```bash
    git clone https://github.com/casbin/casbin-cpp.git
    ```

2. Update `wheel setuptools`:
    ```bash
    python -m pip install --upgrade wheel setuptools
    ```
    
3. Install the `pycasbin` module:
    ```bash
    cd casbin-cpp && pip install --verbose .
    ```

Now, you're ready to go!

### Usage

It is assumed that you have `pycasbin` module correctly installed on your system.

First, we import the `pycasbin` module to a python source file:

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

Rest of the method's name is on par with `casbin-cpp`.

### Benchmark

Pycasbin use `pytest` for benchmark.

Install `pytest` and `pycasbin` in your local machine, then run the benchmark by `python3 -m pytest --benchmark-verbose --benchmark-columns=mean,stddev,iqr,ops,rounds casbin-cpp/pycasbin/benchmarks/benchmark_model.py`.

#### Summary

This sums up the basic usage of `pycasbin` module:

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

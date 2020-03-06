# Casbin Library for C/C++

![workflow](https://github.com/casbin/casbin-cpp/workflows/ci_meson/badge.svg)

This is a powerful and efficient open-source access control library for C/C++ projects. It provides support for enforcing authorization based on various [access control models](https://en.wikipedia.org/wiki/Computer_security_model).

## Usage

If you want to try it, consider installing the `meson` build system, and `ninja` must also be installed with it. For example, on the fedora platform, run `dnf install meson`.

Then:

```bash
git clone git@github.com:casbin/casbin-cpp.git
# or `git clone https://github.com/casbin/casbin-cpp.git`
cd casbin-cpp

# start build
meson build
ninja -C build # -j8
```

### For Developers

```bash
# start install
cd build
meson install
```

Now it should be added to your system.

### For Contributors

In addition, the two subcommands `release` and `format` are provided for easy use.

Just run `ninja -C build <subcommand>`.

_**Note:**_

- Since the `format` script relies on `clang-format`, consider installing it.
- At least make sure that the code is formatted and can be built locally before submission.

## License

This project is licensed under the [Apache 2.0 license](LICENSE).

## Contact

If you have any issues or feature requests, please contact us. PR is welcomed.

- <https://github.com/casbin/casbin-cpp/issues>
- Tencent QQ group: [546057381](//shang.qq.com/wpa/qunwpa?idkey=8ac8b91fc97ace3d383d0035f7aa06f7d670fd8e8d4837347354a31c18fac885)

# libeva

Libeva is a free and open-source cross platform WebRTC library, providing web browsers and mobile applications with real-time communication.

Supported operating systems

- Linux Debian 9, Debian 10, Ubuntu 16.04 and Ubuntu 18.04
- Windows 8, 8.1, 10, Windows Server 2012, Windows Server 2016 and Windows Server 2019

# Deps

```
git clone https://github.com/cisco/libsrtp
cd libsrtp
mkdir build
cd build
cmake ..

git clone https://github.com/janbar/openssl-cmake
cd openssl-cmake
mkdir build
cd build
cmake ..
```

# Building libeva

Install Visual Studio & cmake

```
wget "https://github.com/Kitware/CMake/releases/download/v3.18.0-rc3/cmake-3.18.0-rc3-win64-x64.msi"
cd libeva
mkdir build
cd build
cmake ..
```


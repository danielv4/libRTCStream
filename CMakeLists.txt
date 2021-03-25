cmake_minimum_required(VERSION 2.8)

project(libeva)

link_directories("${CMAKE_SOURCE_DIR}/lib")

include_directories(${CMAKE_SOURCE_DIR}/include)

add_definitions(-DCMAKE_WINDOWS_EXPORT_ALL_SYMBOLS=True -DWIN32_LEAN_AND_MEAN -D_CRT_SECURE_NO_WARNINGS -DNOMINMAX -DWIN32)

add_library(libeva SHARED 
	libeva.cpp
	adler32.c
	compress.c
	crc32.c
	deflate.c
	gzclose.c
	gzlib.c
	gzread.c
	gzwrite.c
	infback.c
	inffast.c
	inflate.c
	inftrees.c
	trees.c
	uncompr.c
	zutil.c
)

target_link_libraries(libeva srtp2 libcrypto Ws2_32 libssl dmoguids wmcodecdspuuid winmm crypt32 iphlpapi secur32 amstrmid msdmo)
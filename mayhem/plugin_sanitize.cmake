# Included after project() in src/CMakeLists.txt (CMAKE_PROJECT_INCLUDE from mayhem/build.sh), the
# directory that defines the plugin target. Relaxes UBSan's array-bounds check on GBI.cpp ONLY:
# GBIInfo::loadMicrocode's F3DEX3 name probe (std::transform over name_buffer, a char[6]) trips it
# on every microcode load, before any guest data matters. Every other plugin file keeps
# -fsanitize=array-bounds (gSP.vertices, the matrix stack, gDP.tiles, TMEM are indexed by guest data).
set_source_files_properties(GBI.cpp PROPERTIES COMPILE_OPTIONS "-fno-sanitize=array-bounds")

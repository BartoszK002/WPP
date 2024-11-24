# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

# If CMAKE_DISABLE_SOURCE_CHANGES is set to true and the source directory is an
# existing directory in our source tree, calling file(MAKE_DIRECTORY) on it
# would cause a fatal error, even though it would be a no-op.
if(NOT EXISTS "C:/Users/BK/Documents/GitHub/WPP/build/_deps/crow-src")
  file(MAKE_DIRECTORY "C:/Users/BK/Documents/GitHub/WPP/build/_deps/crow-src")
endif()
file(MAKE_DIRECTORY
  "C:/Users/BK/Documents/GitHub/WPP/build/_deps/crow-build"
  "C:/Users/BK/Documents/GitHub/WPP/build/_deps/crow-subbuild/crow-populate-prefix"
  "C:/Users/BK/Documents/GitHub/WPP/build/_deps/crow-subbuild/crow-populate-prefix/tmp"
  "C:/Users/BK/Documents/GitHub/WPP/build/_deps/crow-subbuild/crow-populate-prefix/src/crow-populate-stamp"
  "C:/Users/BK/Documents/GitHub/WPP/build/_deps/crow-subbuild/crow-populate-prefix/src"
  "C:/Users/BK/Documents/GitHub/WPP/build/_deps/crow-subbuild/crow-populate-prefix/src/crow-populate-stamp"
)

set(configSubDirs Debug)
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "C:/Users/BK/Documents/GitHub/WPP/build/_deps/crow-subbuild/crow-populate-prefix/src/crow-populate-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "C:/Users/BK/Documents/GitHub/WPP/build/_deps/crow-subbuild/crow-populate-prefix/src/crow-populate-stamp${cfgdir}") # cfgdir has leading slash
endif()

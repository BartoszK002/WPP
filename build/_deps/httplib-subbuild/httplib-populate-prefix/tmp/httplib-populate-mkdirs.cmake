# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION ${CMAKE_VERSION}) # this file comes with cmake

# If CMAKE_DISABLE_SOURCE_CHANGES is set to true and the source directory is an
# existing directory in our source tree, calling file(MAKE_DIRECTORY) on it
# would cause a fatal error, even though it would be a no-op.
if(NOT EXISTS "C:/Users/BK/Documents/GitHub/WPP/build/_deps/httplib-src")
  file(MAKE_DIRECTORY "C:/Users/BK/Documents/GitHub/WPP/build/_deps/httplib-src")
endif()
file(MAKE_DIRECTORY
  "C:/Users/BK/Documents/GitHub/WPP/build/_deps/httplib-build"
  "C:/Users/BK/Documents/GitHub/WPP/build/_deps/httplib-subbuild/httplib-populate-prefix"
  "C:/Users/BK/Documents/GitHub/WPP/build/_deps/httplib-subbuild/httplib-populate-prefix/tmp"
  "C:/Users/BK/Documents/GitHub/WPP/build/_deps/httplib-subbuild/httplib-populate-prefix/src/httplib-populate-stamp"
  "C:/Users/BK/Documents/GitHub/WPP/build/_deps/httplib-subbuild/httplib-populate-prefix/src"
  "C:/Users/BK/Documents/GitHub/WPP/build/_deps/httplib-subbuild/httplib-populate-prefix/src/httplib-populate-stamp"
)

set(configSubDirs Debug)
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "C:/Users/BK/Documents/GitHub/WPP/build/_deps/httplib-subbuild/httplib-populate-prefix/src/httplib-populate-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "C:/Users/BK/Documents/GitHub/WPP/build/_deps/httplib-subbuild/httplib-populate-prefix/src/httplib-populate-stamp${cfgdir}") # cfgdir has leading slash
endif()

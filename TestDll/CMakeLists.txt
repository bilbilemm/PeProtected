project(TestDll)

#add_executable(TestDll)
add_library(TestDll SHARED)

enable_language(ASM_MASM)

#添加引用
target_include_directories(TestDll INTERFACE "./")

#依赖库
target_link_libraries(TestDll 
PRIVATE 

PUBLIC

    )

 target_compile_definitions(TestDll PRIVATE kProjectSourceDir=\"${CMAKE_SOURCE_DIR}/\")

#编译代码
file(GLOB_RECURSE TestDll_HEADERS RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "*.h") 
file(GLOB_RECURSE TestDll_SRC  RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "*.cpp") 
file(GLOB_RECURSE TestDll_ASM RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "*.asm") 
target_sources(TestDll
PRIVATE
     ${TestDll_HEADERS}
     ${TestDll_SRC}
     ${TestDll_ASM}
)

#虚拟目录
set_target_properties (TestDll PROPERTIES
    FOLDER TestDll
)

MACRO(SOURCE_GROUP_BY_FOLDER target)        # 将源文件和头文件进行分组
    SET(SOURCE_GROUP_DELIMITER "/")
    SET(last_dir "")
    SET(files "")
    FOREACH(file ${${target}_SRC} ${${target}_HEADERS} ${${target}_ASM})
        GET_FILENAME_COMPONENT(dir "${file}" PATH)
        IF (NOT "${dir}" STREQUAL "${last_dir}")
            IF (files)
                SOURCE_GROUP("${last_dir}" FILES ${files})
            ENDIF (files)
            SET(files "")
        ENDIF (NOT "${dir}" STREQUAL "${last_dir}")
        SET(files ${files} ${file})
        SET(last_dir "${dir}")
    ENDFOREACH(file)
    IF (files)
        SOURCE_GROUP("${last_dir}" FILES ${files})
    ENDIF (files)
ENDMACRO(SOURCE_GROUP_BY_FOLDER)

set(MODEL "TestDll")
SOURCE_GROUP_BY_FOLDER(${MODEL})
set_project("TermuxAIOverlay")
set_version("1.1.0")
set_languages("c++26")

add_includedirs("include")

target("overlay_engine")
    set_kind("static")
    add_files("src/overlay_engine.cpp")
    add_links("jsoncpp", "ssl", "crypto")

target("overlay_agent")
    set_kind("binary")
    add_files("src/main.cpp")
    add_deps("overlay_engine")

target("test_overlay")
    set_kind("binary")
    add_files("tests/test_overlay.cpp")
    add_deps("overlay_engine")

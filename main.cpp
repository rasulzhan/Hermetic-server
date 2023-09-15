
#include "uploader.h"

#include "common/WLoger/Include/WLoger.h"

#include <fstream>

// GLEW
#include "GL/glew.h"

// Dear Imgui
#define IMGUI_IMPL_OPENGL_LOADER_CUSTOM 1

#include <imgui.h>
#include <backend/imgui_impl_glfw.h>
#include <backend/imgui_impl_opengl3.h>

#if defined(IMGUI_IMPL_OPENGL_LOADER_GL3W)
#include <GL/gl3w.h>            // Initialize with gl3wInit()
#elif defined(IMGUI_IMPL_OPENGL_LOADER_GLEW)
#include <GL/glew.h>            // Initialize with glewInit()
#elif defined(IMGUI_IMPL_OPENGL_LOADER_GLAD)
#include <glad/glad.h>          // Initialize with gladLoadGL()
#elif defined(IMGUI_IMPL_OPENGL_LOADER_GLBINDING2)
#define GLFW_INCLUDE_NONE       // GLFW including OpenGL headers causes ambiguity or multiple definition errors.
#include <glbinding/Binding.h>  // Initialize with glbinding::Binding::initialize()
#include <glbinding/gl/gl.h>
using namespace gl;
#elif defined(IMGUI_IMPL_OPENGL_LOADER_GLBINDING3)
#define GLFW_INCLUDE_NONE       // GLFW including OpenGL headers causes ambiguity or multiple definition errors.
#include <glbinding/glbinding.h>// Initialize with glbinding::initialize()
#include <glbinding/gl/gl.h>
using namespace gl;
#else
#include IMGUI_IMPL_OPENGL_LOADER_CUSTOM
#endif

#include <GLFW/glfw3.h>

// std
#include <iostream>

// #include "common/mdump.h"

// Global Variables
bool GlobalRunning = true;

void LogError(const char *formated_string, const char *error_message)
{
    std::cerr << formated_string << " " << error_message << std::endl;
}

void error_callback(int error, const char* msg) {
	std::string s;
	s = " [" + std::to_string(error) + "] " + msg + '\n';
	std::cerr << s << std::endl;
}

void RenderToOutput()
{}

int main(int ac, char **av)
{

    std::cout << "Start test! " << std::endl;
    // SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER) TopLevelFilter);
    if (!glfwInit())
        return 1;
    (void)(ac);
    (void)(av);
    std::ofstream log_out = std::ofstream(".\\client_log.log");
    ATTACH_STRAEM(WL_INFO, std::cout);
    ATTACH_STRAEM(WL_ERROR, std::cout);
    ATTACH_STRAEM(WL_WARNING, std::cout);
    ATTACH_STRAEM(WL_INFO, log_out);
    ATTACH_STRAEM(WL_ERROR, log_out);
    ATTACH_STRAEM(WL_WARNING, log_out);

    const char* glsl_version = "#version 330";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);  // 3.2+ only
    glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);
    glfwWindowHint(GLFW_VISIBLE, GL_FALSE);
    glfwWindowHint(GLFW_SAMPLES, 4);

    glfwSetErrorCallback(error_callback);

    GLFWwindow* window = nullptr;
    window = glfwCreateWindow(1440, 1024, "Darwin", NULL, NULL);
    if (window == NULL)
        return 1;

    glfwSetInputMode(window, GLFW_CURSOR, GLFW_CURSOR_NORMAL);
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1); // Enable vsync



    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO &io = ImGui::GetIO();
    (void)io;
    io.ConfigFlags |= ImGuiConfigFlags_ViewportsEnable | ImGuiConfigFlags_DockingEnable;
    io.MouseDrawCursor = false;
    io.Fonts->Clear();
    ImFontConfig config;
    config.OversampleH = 4;
    config.OversampleV = 4;
    config.GlyphExtraSpacing.x = 1.0f;
    config.SizePixels = 16;
    io.Fonts->Clear();
    // auto font = io.Fonts->AddFontDefault(&config);
    auto font = io.Fonts->AddFontFromFileTTF("./res/fonts/Roboto-Medium.ttf", 16);
    io.FontDefault = font;
    io.Fonts->Build();
    ImGui::StyleColorsDark();
    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init(glsl_version);

    while (GlobalRunning) {
        glfwPollEvents();// glfwWaitEvents();


        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

//        ImGui::ShowDemoWindow();

        UpdateAndRender(0, 0, 1440, 1024);

        ImGui::Render();
        glViewport(0, 0, 1440, 1024);
        glClear(GL_COLOR_BUFFER_BIT);

        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

        if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
        {
            GLFWwindow* backup_current_context = glfwGetCurrentContext();
            ImGui::UpdatePlatformWindows();
            ImGui::RenderPlatformWindowsDefault();
            glfwMakeContextCurrent(backup_current_context);
        }

        glfwSwapBuffers(window);
    }
    log_out.close();
    return 0;
}

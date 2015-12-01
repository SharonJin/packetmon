#pragma warning(disable: 130 4005)
#pragma comment(lib, "GLFW/glfw3.lib")
#pragma comment(lib, "opengl32.lib")
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "x64/release/keyhook.lib")

#define WIN32_LEAN_AND_MEAN

#include <GLFW/glfw3.h>
#include <imgui.h>
#include "imgui/imgui_impl_glfw.h"

#include <thread>
#include <mutex>
#include <string>
#include <vector>

#include <Windows.h>
#include <mmsystem.h>

#include "wsock.h"
#include "filter.h"
#include "winhttp.h"
#include "keyhook/keyhook.h"


#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>

#define INTERVAL_SLEEP 16  // 33ms
#define INTERVAL_POST 3000 

namespace shared {
    __declspec(dllimport) int keyhook_vk;
    __declspec(dllimport) bool keyhook_enabled;
}

int WinMain(HINSTANCE hinst, HINSTANCE, LPSTR, int) {
#if DEBUG
    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
#endif

    // setup window
    glfwSetErrorCallback([](int error, const char* description) {
        fprintf(stderr, "Error %d: %s\n", error, description);
    });
    if (!glfwInit())
        exit(1);
    GLFWwindow* window = glfwCreateWindow(800, 480, "packetmon", NULL, NULL);
    glfwMakeContextCurrent(window);

    // setup ImGui binding
    ImGui_ImplGlfw_Init(window, true);

    // keylock vkey code
    char keyhook_vk_input[4] = "116";
    shared::keyhook_vk = 0x74;
    keyhook_install();

    // init winsock
    packetmon::wsock ws;
    if (!ws.init()) return false;
    if (!ws.query()) return false;
    if (!ws.bind(0)) return false;

    // init filter
    packetmon::filter filter;
    filter.init();

    // init winhttp
    packetmon::winhttp winhttp(L"cpirc", L"/cpirc", false);

    // thread exit flag
    bool winmain_exit = false;

    // packet capture thread
    std::mutex mtx;
    std::vector<std::shared_ptr<packetmon::TcpPacket>> receivedPackets;
    std::thread capturethread([&winmain_exit, &ws, &receivedPackets, &filter, &mtx] { 
        for (;;) {
            auto rp = ws.recv();
            if (rp == nullptr) continue;

            std::unique_lock<std::mutex> uniq(mtx);
            if (winmain_exit == true)
                break;

            if (!filter.active)
                continue;

            if (filter.doFilter(rp) == true) {
                // save filtered packet
                receivedPackets.push_back(rp);
            }
        }
        return nullptr;
    });

    // http post thread
    std::thread postthread([&winmain_exit, &winhttp, &receivedPackets, &mtx] { 
        int pos = 0;
        for (;;) {
            Sleep(INTERVAL_SLEEP);

            std::string comment = "";
            {
                std::unique_lock<std::mutex> uniq(mtx);

                if (winmain_exit == true)
                    break;

                if (pos == receivedPackets.size())
                    continue;

                packetmon::TcpPacket* tp = receivedPackets[pos].get();
                comment = std::string(tp->comment);
            }
            winhttp.post(comment);

            Sleep(INTERVAL_POST);
            pos++;
        }
        return nullptr;
    });

    // main loop
    while (!glfwWindowShouldClose(window)) {
        Sleep(INTERVAL_SLEEP);

        glfwPollEvents();
        ImGui_ImplGlfw_NewFrame();

        if (ImGui::Begin("recent matched packets")) {
            // listbox (ip / port / packet hex / len)
            ImGui::Columns(4, "Received");
            ImGui::Separator();
            ImGui::Text("ip"); ImGui::NextColumn();
            ImGui::Text("port"); ImGui::NextColumn();
            ImGui::Text("len"); ImGui::NextColumn();
            ImGui::Text("hex"); ImGui::NextColumn();
            ImGui::Separator();
            static int selected = -1;

            for (int i = (int)receivedPackets.size() - 1, j = 0; i >= 0; i--, j++) {
                // rendering
                if (ImGui::Selectable(
                    (receivedPackets[i]->ip_src_string + " -> " + receivedPackets[i]->ip_dst_string).c_str(),
                    selected == i, ImGuiSelectableFlags_SpanAllColumns))
                    selected = i;
                ImGui::NextColumn();
                ImGui::Text(std::to_string(ntohs(receivedPackets[i]->tcp.th_sport)).c_str()); ImGui::NextColumn();
                ImGui::Text(std::to_string(receivedPackets[i]->payload_string.length()).c_str()); ImGui::NextColumn();
                ImGui::Text(receivedPackets[i]->payload_string.c_str()); ImGui::NextColumn();
                if (j > 30) break;
            }
            ImGui::End();
        }

        if (ImGui::Begin("recent matched packets(comment)")) {
            for (int i = (int)receivedPackets.size() - 1, j = 0; i >= 0; i--, j++) {
                if (!receivedPackets[i]->comment.empty()) {
                    ImGui::Text(receivedPackets[i]->comment.c_str());
                }
                if (j > 30) break;
            }
            ImGui::End();
        }

        if (ImGui::Begin("filter")) {
            static int current = 0;
            if (ImGui::Combo("nic", &current, ws.sock_addr_list.c_str()))
                ws.bind(current);
            ImGui::InputText("source ip", filter.filter_ip_src, 17, ImGuiInputTextFlags_::ImGuiInputTextFlags_CharsDecimal);
            ImGui::InputText("destination ip", filter.filter_ip_dst, 17, ImGuiInputTextFlags_::ImGuiInputTextFlags_CharsDecimal);
            ImGui::InputText("tcp sport / dport", filter.filter_port, 6, ImGuiInputTextFlags_::ImGuiInputTextFlags_CharsDecimal);
            if (ImGui::RadioButton("capture thread on", filter.active)) filter.active = true;
            if (ImGui::RadioButton("capture thread off", !filter.active)) filter.active = false;
            if (ImGui::InputText("keyboard lock (vkey in dec)", keyhook_vk_input, 3, ImGuiInputTextFlags_::ImGuiInputTextFlags_CharsDecimal)) {
                shared::keyhook_vk = std::stoi(keyhook_vk_input);
            }
            if (ImGui::Button(shared::keyhook_enabled == 1 ? "keylock on (press to disable)" : "keylock off")) {
                if (shared::keyhook_enabled == 1)
                    shared::keyhook_enabled = 0;
                else
                    shared::keyhook_enabled = 1;
            }
            ImGui::Text("received count: %d, matched count: %d", filter.received_packet_count, filter.matched_packet_count);
            ImGui::End();
        }
        
        // Rendering
        int display_w, display_h;
        glfwGetFramebufferSize(window, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h);
        glClearColor(0.22f, 0.22f, 0.22f, 0);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui::Render();
        glfwSwapBuffers(window);
    }

    // Cleanup
    ImGui_ImplGlfw_Shutdown();
    glfwTerminate();

    winmain_exit = true;
    postthread.join();
    capturethread.join();
    keyhook_uninstall();
    receivedPackets.clear();

    ws.cleanup();
    return 0;
}
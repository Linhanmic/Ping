#include "Ping.h"

/**
 * @brief Main function to run the ping program.
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return Exit status.
 */
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: ping <hostname/IP>" << std::endl;
        return -1;
    }

    Ping ping(argv[1]);
    ping.run();

    return 0;
}

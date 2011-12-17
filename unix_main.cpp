#include <getopt.h>
#include <stdlib.h>
#include <iostream>

#include "sys/cfg.h"
#include "net/cfg.h"
#include "sys/main.h"
#include "version.h"

#include "cmn/pthread_cpu_time.h"

static void help(std::ostream& out, int argc, char* argv[])
{
out << "usage: " << argv[0] << " <config file name>" << std::endl;
}

static const char options[] = "hvD";
static const struct option long_options[] = {
    { "help",       0,  0,  'h' },
    { "version",    0,  0,  'v' },
    { "daemon",     0,  0,  'D' },
    { 0,            0,  0,   0  },
};

int main(int argc, char* argv[])
{
timespec tbegin = get_pthread_time_mark();
bool demonize = false;
int option_index = 0;
while ( true )
    {
    int option = getopt_long( argc, argv, options, long_options, &option_index );
    if ( -1 == option )
        {
        break;
        }

    switch ( option )
        {
        case 'h':
            help( std::cout, argc, argv );
            return EXIT_SUCCESS;
        case 'v':
            version( std::cout );
            return EXIT_SUCCESS;
        case 'D':
            demonize = true;
            break;
        default:
            help( std::cerr, argc, argv );
            return EXIT_FAILURE;
        }
    }

if ( optind == argc )
    {
    std::cerr << "set config file name" << std::endl;
    return EXIT_FAILURE;
    }

pugi::xml_document cfgfile;
pugi::xml_parse_result result = cfgfile.load_file( argv[optind] );
pugi::xml_node cfg = cfgfile.first_child();
if ( !result || !cfg )
    {
    std::cerr << "invalid config file" << std::endl;
    return EXIT_FAILURE;
    }

std::cerr << get_time_diff_nsec(tbegin, get_pthread_time_mark()) << std::endl;

try
    {
    sys::check_cfg( cfg );
    net::check_cfg( cfg );
    }
catch (cmn::exception& e)
    {
    std::cerr << e.what() << std::endl;
    return EXIT_FAILURE;
    }
//TODO: detach here
return sys::run( cfg );
}


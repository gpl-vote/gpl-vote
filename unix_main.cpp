#include <getopt.h>
#include <stdlib.h>
#include <iostream>

#include "sys/cfg.h"
#include "net/cfg.h"
#include "sys/main.h"
#include "version.h"

static void help(std::ostream& out, int argc, char* argv[], int topic = 0)
{
    switch(topic)
    {
        case 'c':
            out << "todo: man " << argv[0] << " -c|--config" << std::endl;
            break;
        case 'D':
            out << "todo: man " << argv[0] << " -D|--daemon" << std::endl;
            break;
        case 'v':
            out << "todo: man " << argv[0] << " -v|--version" << std::endl;
            break;
        default: 
            out << "usage: " << argv[0] << " <config file name>" << std::endl;
            break;
    }
}

int main(int argc, char* argv[])
{
int option_index    = 0;    
int opt_help        = 0;
int opt_version     = 0;
int opt_demonize    = 0;
int opt_config_name = 0;
int opt_default     = 0;
char* config_name   = NULL;
static const char options[] = "-:hvDc:W;";
static const struct option long_options[] = {
    { "help",       no_argument,        &opt_help,          'h' },
    { "version",    no_argument,        &opt_version,       'v' },
    { "daemon",     no_argument,        &opt_demonize,      'D' },
    { "config",     required_argument,  NULL,               'c' },
    { 0,            0,                  0,                  0   },
};

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
            opt_help = option;
            break;
        case 'v':
            opt_version = option;
            break;
        case 'D':
            opt_demonize = option;
            break;
        case 'c':
            opt_config_name = option;
            if (NULL != optarg)
            {
                config_name = optarg;
            }
            break;
        case 0: // getopt_long set var
#ifdef _DEBUG_            
            std::cerr << "option " << long_options[option_index].name;
            if (optarg) std::cerr << " with arg " << optarg;
            std::cerr << std::endl;
#endif            
            break;
        case 1:
            if (!opt_config_name && NULL != optarg)
            {
                opt_config_name = 1;
                config_name = optarg;
            }
            break;
        default:
            opt_default = 1;
            break;
        }
    }

#ifdef _DEBUG_
std::cerr <<    " help=" << opt_help << " version=" << opt_version << " demonize=" << opt_demonize << " conf_name=" << opt_config_name << " default=" << opt_default;
if (config_name != NULL) std::cerr << " name=" << config_name;
std::cerr << std::endl;
#endif

if (opt_help)  
{
    help( std::cout, argc, argv, opt_version | opt_demonize | opt_config_name );
    return EXIT_SUCCESS;
}
if (opt_version)
{
    version( std::cout );
    return EXIT_SUCCESS;    
}
if (opt_default)
{
    help( std::cerr, argc, argv );
    return EXIT_FAILURE;
}
if ( !opt_config_name || NULL == config_name )
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


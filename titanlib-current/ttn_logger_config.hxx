/**
 * $Id$
 *
 */

#ifndef LOG_CONFIG_HXX
#define LOG_CONFIG_HXX

#include "global.h"
#include "TitaxConf.h"

struct logger_config_t : t_tx_logger_daemon_cfg
{

    constexpr 
    logger_config_t() noexcept : t_tx_logger_daemon_cfg{ 

                                    .traffic_pg_cstr =              TX_LOGGER_DAEMON_CFG_PG_CSTR_DEF_VAL,
                                    .titax_pg_cstr =                TX_LOGGER_DAEMON_CFG_INFO_PG_CSTR_DEF_VAL,
                                    .batch_size =                   TX_LOGGER_DAEMON_CFG_BATCH_SIZE_DEF_VAL,
                                    .batch_treshold_div =           TX_LOGGER_DAEMON_CFG_BATCH_TRESHOLD_DEF_VAL,
                                    .delay_max =                    TX_LOGGER_DAEMON_CFG_DELAY_MAX_DEF_VAL,
                                    .delay =                        TX_LOGGER_DAEMON_CFG_DELAY_DEF_VAL,
                                    .if_listen_port =               TX_LOGGER_DAEMON_CFG_IF_LISTEN_PORT_DEF_VAL,
                                    .url_csz =                      TX_LOGGER_DAEMON_CFG_URL_CSZ_DEF_VAL,
                                    .syslog_facility =              TX_LOGGER_DAEMON_CFG_DEFAULT_SYSLOG_FACILITY,
                                    .n_batches_per_stats_write =    TX_LOGGER_DAEMON_CFG_N_BATCHES_PER_STATS_DEFAULT,
                                    .if_listen_on_any =             TX_LOGGER_DAEMON_CFG_IF_LISTEN_ON_ANY_DEF_VAL,
                                    .use_syslog =                   TX_LOGGER_DAEMON_CFG_USE_SYSLOG_DEV_VAL,
                                    .log_only_blocked =             TX_LOGGER_DAEMON_CFG_LOG_ONLY_BLOCKED_DEF_VAL,
                                    .log_loc_stats =                TX_LOGGER_DAEMON_CFG_LOG_LOC_STATS_DEF_VAL,
                                    .log_groups =                   TX_LOGGER_DAEMON_CFG_LOG_GROUPS_DEF_VAL,

                                 }
    {
        /* empty */
    }

    bool reload() noexcept
    {

        return tx_logger_daemon_read_conf_file(this);
        
    }

    friend std::ostream& operator<<( std::ostream & out, const logger_config_t & conf ) noexcept 
    {
        return  out << "-------------------------------------------------------" <<std::endl
                    << "Configuration:"         << std::endl
                    << "\t-batch_size:"         << conf.batch_size          << std::endl
                    << "\t-batch_treshold:"     << conf.batch_treshold_div  << std::endl
                    << "\t-delay_max:"          << conf.delay_max           << std::endl
                    << "\t-delay:"              << conf.delay               << std::endl
                    << "\t-traffic_pg_cstr:"    << conf.traffic_pg_cstr     << std::endl
                    << "\t-titax_pg_cstr:"      << conf.titax_pg_cstr       << std::endl
                    << "\t-if_listen_on_any:"   << conf.if_listen_on_any    << std::endl
                    << "\t-if_listen_port:"     << conf.if_listen_port      << std::endl
                    << "\t-use_syslog:"         << conf.use_syslog          << std::endl
                    << "\t-syslog_facility:"    << conf.syslog_facility     << std::endl
                    << "\t-log_only_blocked:"   << conf.log_only_blocked    << std::endl
                    << "\t-log_loc_stats:"      << conf.log_loc_stats       << std::endl
                    << "\t-log_groups:"         << conf.log_groups          << std::endl;
    }


}; /* logger_config_t */



#endif /* LOG_CONFIG_HXX */

/* vim: set ts=4 sw=4 et : */

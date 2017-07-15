using Microsoft.Owin;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.ServiceModel.Channels;
using System.Web;
using System.Web.Http;
using System.Web.Http.Controllers;

namespace dotnet_ipfilter
{
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
    public class FilterIPAttribute : AuthorizeAttribute
    {
        #region Allowed
        /// <summary>
        /// Allowed ip sources for selected controller or endpoint
        /// You can assign multiple ips by separating them with comma
        /// e.g: "8.8.8.8,127.0.0.1"
        /// </summary>
        public String AllowedIPs { get; set; }

        /// <summary>
        /// Allowed masked ip sources for selected controller or endpoint
        /// You can assign multiple ips by separating them with semicolon
        /// e.g: "10.11.0.0;255.255.0.0"
        /// </summary>
        public String AllowedMaskedIPs { get; set; }

        /// <summary>
        /// Reads allowed ips from web.config with selected key as string,
        /// follows the same format as AllowedIPs
        /// e.g: "8.8.8.8,127.0.0.1"
        /// </summary>
        public String ConfigKeyAllowedIPs { get; set; }

        /// <summary>
        /// Read allowed masked ips from web.config with selected key as string,
        /// follows the same format as AllowedMaskedIPs
        /// e.g: "10.11.0.0;255.255.0.0"
        /// </summary>
        public String ConfigKeyAllowedMaskedIPs { get; set; }

        IPList allowedIPListToCheck = new IPList();
        #endregion

        #region Denied
        /// <summary>
        /// Denied ip sources for selected controller or endpoint
        /// You can assign multiple ips by separting them with comma
        /// e.g: "8.8.8.8,127.0.0.1"
        /// </summary>
        public String DeniedIPs { get; set; }

        /// <summary>
        /// Denied masked ip sources for selected controller or endpoint
        /// You can assign multiple ips by separating them with semicolon
        /// e.g: "10.11.0.0;255.255.0.0"
        /// </summary>
        public String DeniedMaskedIPs { get; set; }

        /// <summary>
        /// Reads denied ips from web.config with selected key as string,
        /// follows the same format as AllowedIPs
        /// e.g: "8.8.8.8,127.0.0.1"
        /// </summary>
        public String ConfigKeyDeniedIPs { get; set; }

        /// <summary>
        /// Read denied masked ips from web.config with selected key as string,
        /// follows the same format as AllowedMaskedIPs
        /// e.g: "10.11.0.0;255.255.0.0"
        /// </summary>
        public String ConfigKeyDeniedMaskedIPs { get; set; }

        IPList deniedIPListToCheck = new IPList();
        #endregion

        // Strings for identify how current web app is being hosted (for finding current ip)
        private const string _HttpContext = "MS_HttpContext";
        private const string _RemoteEndpointMessage = "System.ServiceModel.Channels.RemoteEndpointMessageProperty";
        private const string _OwinContext = "MS_OwinContext";

        /// <summary>
        /// Fetches current client ip address and tries to match it against allow/deny list
        /// and then returns true if client is allowed and false if it's being denied
        /// </summary>
        /// <param name="actionContext"></param>
        /// <returns>Returns true if current user ip address is allowed</returns>
        protected override bool IsAuthorized(HttpActionContext actionContext)
        {
            if (actionContext == null)
                throw new ArgumentNullException("actionContext");

            var userIpAddress = "";

            // web-hosting
            if (actionContext.Request.Properties.ContainsKey(_HttpContext))
            {
                userIpAddress = ((HttpContextWrapper)actionContext.Request.Properties[_HttpContext]).Request.UserHostName;
            }

            // self-hosting
            if (actionContext.Request.Properties.ContainsKey(_RemoteEndpointMessage))
            {
                var remoteEndpoint = (RemoteEndpointMessageProperty)actionContext.Request.Properties[_RemoteEndpointMessage];
                if (remoteEndpoint != null)
                {
                    userIpAddress = remoteEndpoint.Address;
                }
            }

            // self-hosting using owin
            if (actionContext.Request.Properties.ContainsKey(_OwinContext))
            {
                var owinContext = (OwinContext)actionContext.Request.Properties[_OwinContext];
                if (owinContext != null)
                {
                    userIpAddress = owinContext.Request.RemoteIpAddress;
                }
            }

            try
            {
                bool ipAllowed = CheckAllowedIPs(userIpAddress);

                bool ipDenied = CheckDeniedIPs(userIpAddress);

                bool finallyAllowed = ipAllowed && !ipDenied;

                return finallyAllowed;
            }
            catch (Exception ex)
            {
                // TODO: Add logging here in the future if ip check fails
                throw ex;
            }
        }

        /// <summary>
        /// Goes through all allowed IPs (defined when using the filter)
        /// </summary>
        /// <param name="userIpAddress"></param>
        /// <returns>Returns true if given ip is allowed</returns>
        private bool CheckAllowedIPs(string userIpAddress)
        {
            // Populate the IPList with the Single IPs
            if (!string.IsNullOrEmpty(AllowedIPs))
            {
                SplitAndAddSingleIPs(AllowedIPs, allowedIPListToCheck);
            }

            // Populate the IPList with the Masked IPs
            if (!string.IsNullOrEmpty(AllowedMaskedIPs))
            {
                SplitAndAddMaskedIPs(AllowedMaskedIPs, allowedIPListToCheck);
            }

            // Check if there are more settings from the configuration (Web.config)
            if (!string.IsNullOrEmpty(ConfigKeyAllowedIPs))
            {
                string configurationAllowedAdminSingleIPs = ConfigurationManager.AppSettings[ConfigKeyAllowedIPs];
                if (!string.IsNullOrEmpty(configurationAllowedAdminSingleIPs))
                {
                    SplitAndAddSingleIPs(configurationAllowedAdminSingleIPs, allowedIPListToCheck);
                }
            }

            if (!string.IsNullOrEmpty(ConfigKeyAllowedMaskedIPs))
            {
                string configurationAllowedAdminMaskedIPs = ConfigurationManager.AppSettings[ConfigKeyAllowedMaskedIPs];
                if (!string.IsNullOrEmpty(configurationAllowedAdminMaskedIPs))
                {
                    SplitAndAddMaskedIPs(configurationAllowedAdminMaskedIPs, allowedIPListToCheck);
                }
            }

            return allowedIPListToCheck.CheckNumber(userIpAddress);
        }

        /// <summary>
        /// Goes through all denied IPs (defined when using the filter)
        /// </summary>
        /// <param name="userIpAddress"></param>
        /// <returns>Returns true if given ip is denied</returns>
        private bool CheckDeniedIPs(string userIpAddress)
        {
            // Populate the IPList with the Single IPs
            if (!string.IsNullOrEmpty(DeniedIPs))
            {
                SplitAndAddSingleIPs(DeniedIPs, deniedIPListToCheck);
            }

            // Populate the IPList with the Masked IPs
            if (!string.IsNullOrEmpty(DeniedMaskedIPs))
            {
                SplitAndAddMaskedIPs(DeniedMaskedIPs, deniedIPListToCheck);
            }

            // Check if there are more settings from the configuration (Web.config)
            if (!string.IsNullOrEmpty(ConfigKeyDeniedIPs))
            {
                string configurationDeniedAdminSingleIPs = ConfigurationManager.AppSettings[ConfigKeyDeniedIPs];
                if (!string.IsNullOrEmpty(configurationDeniedAdminSingleIPs))
                {
                    SplitAndAddSingleIPs(configurationDeniedAdminSingleIPs, deniedIPListToCheck);
                }
            }

            if (!string.IsNullOrEmpty(ConfigKeyDeniedMaskedIPs))
            {
                string configurationDeniedAdminMaskedIPs = ConfigurationManager.AppSettings[ConfigKeyDeniedMaskedIPs];
                if (!string.IsNullOrEmpty(configurationDeniedAdminMaskedIPs))
                {
                    SplitAndAddMaskedIPs(configurationDeniedAdminMaskedIPs, deniedIPListToCheck);
                }
            }

            return deniedIPListToCheck.CheckNumber(userIpAddress);
        }

        private void SplitAndAddSingleIPs(string ips, IPList list)
        {
            var splitSingleIPs = ips.Split(',');
            foreach (string ip in splitSingleIPs)
                list.Add(ip);
        }

        private void SplitAndAddMaskedIPs(string ips, IPList list)
        {
            var splitMaskedIPs = ips.Split(',');
            foreach (string maskedIp in splitMaskedIPs)
            {
                var ipAndMask = maskedIp.Split(';');
                list.Add(ipAndMask[0], ipAndMask[1]); // IP;MASK
            }
        }

        public override void OnAuthorization(HttpActionContext actionContext)
        {
            base.OnAuthorization(actionContext);
        }
    }
}

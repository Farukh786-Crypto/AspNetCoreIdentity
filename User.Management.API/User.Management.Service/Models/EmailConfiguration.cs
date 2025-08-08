using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace User.Management.Service.Models
{
    public class EmailConfiguration
    {
        public string From { get; set; } = string.Empty;
        public string? SmtpServer { get; set; }
        public int Port { get; set; }
        public string UserName { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
    }
}

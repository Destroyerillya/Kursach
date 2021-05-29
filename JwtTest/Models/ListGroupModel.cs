using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;
using JwtTest.EF;

namespace JwtTest.Models
{
    public class ListGroupModel
    {
        public List<Group> Groups{ get; set; }
        
        public virtual Person Sender { get; set;}
        
        public string Title { get; set; }
    }
}

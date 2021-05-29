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
    public class DialogModel
    {
        public IQueryable<PersonalMessage> Messages{ get; set; }
        
        public int Receiver { get; set;}
        
        public string MessageText { get; set;}
    }
}

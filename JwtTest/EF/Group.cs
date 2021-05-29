using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;
using JwtTest.EF;

namespace JwtTest.EF
{
    public class Group
    {
        public int Id { get; set; }
        [DisplayName("Название группы")]
        public string Title { get; set; }
        public virtual List<Person> MembersOfTheGroup { get; set; }
    }
}
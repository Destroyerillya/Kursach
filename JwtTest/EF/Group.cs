using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace JwtTest.EF
{
    public class Group
    {
        public int Id { get; set; }
        public string Title { get; set; }
        public virtual List<Person> MembersOfTheGroup { get; set; }
    }
}
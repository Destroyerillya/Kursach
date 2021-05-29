using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace JwtTest.EF
{
    public class GroupMessage
    {
        public int Id { get; set; }
        public DateTime TimeOfDispatch { get; set; }
        public string MessageText { get; set; }
        public virtual Group RecipientGroup { get; set; }
        public virtual Person Sender { get; set; }
    }
}
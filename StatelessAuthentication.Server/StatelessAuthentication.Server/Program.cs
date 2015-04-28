using System;
using ServiceStack.Text;

namespace StatelessAuthentication.Server
{
    class Program
    {
        static void Main(string[] args)
        {
            new AppHost().Init().Start("http://*:8088/");
            "ServiceStack SelfHost listening at http://localhost:8088 ".Print();

            Console.ReadLine();
        }
    }
}

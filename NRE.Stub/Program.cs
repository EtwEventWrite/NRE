using System;

namespace NRE.Stub
{
    static class Program
    {
        [STAThread]
        static void Main(string[] args) => StubEntryPoint.Run(args);
    }
}

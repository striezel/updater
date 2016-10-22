using System;
using System.Collections.Generic;

namespace updater_cli
{
    class Program
    {
        static void Main(string[] args)
        {
            var list = detection.DetectorRegistry.detect();
            foreach (var item in list)
            {
                Console.WriteLine("\"" + item.displayName + "\", version \"" + item.displayVersion + "\"");
                Console.WriteLine("   Install: \"" + item.installPath + "\"");
                Console.WriteLine();
            }

            list = detection.DetectorMSI.detect();
            foreach (var item in list)
            {
                Console.WriteLine("\"" + item.displayName + "\", version \"" + item.displayVersion + "\"");
                Console.WriteLine("   Install: \"" + item.installPath + "\"");
                Console.WriteLine();
            }
        } //Main
    } //class
} //namespace

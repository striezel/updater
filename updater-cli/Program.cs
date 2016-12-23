using System;

namespace updater_cli
{
    class Program
    {
        static void Main(string[] args)
        {
            var listReg = detection.DetectorRegistry.detect();
            listReg.Sort();
            foreach (var item in listReg)
            {
                Console.WriteLine("\"" + item.displayName + "\", version \"" + item.displayVersion + "\"");
                Console.WriteLine("   Install: \"" + item.installPath + "\"");
                Console.WriteLine();
            }
            io.CSVWriter.toCSV(listReg, "installed_reg.csv");
            Console.WriteLine("Hit Enter to continue...");
            Console.ReadLine();

            var listMSI = detection.DetectorMSI.detect();
            listMSI.Sort();
            foreach (var item in listMSI)
            {
                Console.WriteLine("\"" + item.displayName + "\", version \"" + item.displayVersion + "\"");
                Console.WriteLine("   Install: \"" + item.installPath + "\"");
                Console.WriteLine();
            }
            io.CSVWriter.toCSV(listMSI, "installed_msi.csv");
            Console.WriteLine("Hit Enter to continue...");
            Console.ReadLine();

        } //Main
    } //class
} //namespace

/*
    updater, command line interface
    Copyright (C) 2016, 2017  Dirk Stolle

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

using System;
using updater_cli.operations;

namespace updater_cli
{
    class Program
    {
        /// <summary>
        /// NLog.Logger for Program
        /// </summary>
        private static NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Program).FullName);


        /// <summary>
        /// shows the current program version
        /// </summary>
        static void showVersion()
        {
            var asm = System.Reflection.Assembly.GetExecutingAssembly();
            var ver = asm.GetName().Version;
            Console.WriteLine("updater, version " + utility.Version.get());
        }


        static int Main(string[] args)
        {
            utility.Logging.initialize();

            if (args.Length < 1)
            {
                logger.Error("Error: At least one command line argument must be present!");
                return ReturnCodes.rcInvalidParameter;
            }

            Operation op = Operation.Unknown;
            bool autoGetNewer = true;
            bool withAurora = false;

            for (int i = 0; i < args.Length; i++)
            {
                string param = args[i].ToLower();
                switch (param)
                {
                    case "check":
                    case "query":
                    case "status":
                        op = Operation.Check;
                        break;
                    case "detect":
                        op = Operation.Detect;
                        break;
                    case "update":
                    case "upgrade":
                        op = Operation.Update;
                        break;
                    case "--version":
                    case "/v":
                    case "-v":
                        showVersion();
                        return 0;
                    case "--aurora":
                    case "--with-aurora":
                        withAurora = true;
                        break;
                    case "--no-aurora":
                    case "--without-aurora":
                        withAurora = false;
                        break;
                    case "-n":
                    case "/n":
                    case "--newer":
                    case "--auto-get-newer":
                    case "--automatically-get-newer":
                        autoGetNewer = true;
                        break;
                    case "-nn":
                    case "/nn":
                    case "--no-newer":
                    case "--no-auto-get-newer":
                    case "--no-automatically-get-newer":
                        autoGetNewer = false;
                        break;
                    default:
                        logger.Error("Error: " + param + " is not a valid command line option!");
                        return ReturnCodes.rcInvalidParameter;
                } //switch
            } //for

            if (op == Operation.Unknown)
            {
                logger.Error("Error: No operation was specified!");
                return ReturnCodes.rcInvalidParameter;
            }

            IOperation operation = null;
            switch (op)
            {
                case Operation.Detect:
                    operation = new OperationDetect();
                    break;
                case Operation.Check:
                    operation = new SoftwareStatus(autoGetNewer, withAurora);
                    break;
                case Operation.Update:
                    operation = new Update(autoGetNewer, withAurora);
                    break;
                case Operation.Unknown:
                default:
                    logger.Error("Unknown operation was specified! Exiting program.");
                    return ReturnCodes.rcUnknownOperation;
            } //switch
            return operation.perform();
        } //Main
    } //class
} //namespace

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

namespace updater_cli
{
    class Program
    {
        static int Main(string[] args)
        {
            if (args.Length >1)
            {
                Console.WriteLine("Error: No more than one command line argument is allowed!");
                return ReturnCodes.rcInvalidParameter;
            }

            operations.Operation op = operations.Operation.Unknown;
            if (args.Length == 1)
            {
                string command = args[0].ToLower();
                switch (command)
                {
                    case "check":
                    case "query":
                        op = operations.Operation.Check;
                        break;
                    case "detect":
                        op = operations.Operation.Detect;
                        break;
                    case "update":
                        op = operations.Operation.Update;
                        break;
                    default:
                        Console.WriteLine("Error: " + command + " is not a valid operation!");
                        return ReturnCodes.rcInvalidParameter;
                } //switch
            } //if parameter is given

            if (op == operations.Operation.Unknown)
                op = operations.Operation.Check;

            operations.IOperation operation = null;
            switch (op)
            {
                case operations.Operation.Detect:
                    operation = new operations.OperationDetect();
                    break;
                case operations.Operation.Check:
                    operation = new operations.SoftwareStatus();
                    break;
                case operations.Operation.Update:
                    operation = new operations.Update();
                    break;
                case operations.Operation.Unknown:
                default:
                    Console.WriteLine("Unknown operation was specified! Exiting program.");
                    return ReturnCodes.rcUnknownOperation;
            } //switch
            return operation.perform();
        } //Main
    } //class
} //namespace

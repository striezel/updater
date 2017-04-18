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

using updater.operations;

namespace updater
{
    class Program
    {
        /// <summary>
        /// NLog.Logger for Program
        /// </summary>
        private static NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Program).FullName);


        static int Main(string[] args)
        {
            utility.Logging.initialize();

            cli.Options options = new cli.Options();
            int rc = cli.ArgumentParser.parse(args, ref options);
            if (rc != 0)
                return rc;

            //There has to be an operation at least.
            if (options.op == Operation.Unknown)
            {
                logger.Error("Error: No operation was specified!");
                return ReturnCodes.rcInvalidParameter;
            }

            IOperation operation = null;
            switch (options.op)
            {
                case Operation.Detect:
                    operation = new Detect();
                    break;
                case Operation.Check:
                    operation = new SoftwareStatus(options);
                    break;
                case Operation.Update:
                    operation = new Update(options);
                    break;
                case Operation.Id:
                    operation = new IdList(options);
                    break;
                case Operation.Version:
                    operation = new operations.Version();
                    break;
                case Operation.Help:
                    operation = new Help();
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

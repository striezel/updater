/*
    This file is part of the updater command line interface.
    Copyright (C) 2017  Dirk Stolle

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

namespace updater.cli
{
    /// <summary>
    /// Parses command line arguments
    /// </summary>
    public class ArgumentParser
    {
        /// <summary>
        /// NLog.Logger for ArgumentParser
        /// </summary>
        private static NLog.Logger logger = NLog.LogManager.GetLogger(typeof(ArgumentParser).FullName);


        /// <summary>
        /// parses command line arguments
        /// </summary>
        /// <param name="argv"></param>
        /// <returns></returns>
        public static int parse(string[] argv, ref Options opts)
        {
            if (null == opts)
                opts = new Options();
            if (null == argv)
                return 0;
            if (argv.Length < 1)
            {
                logger.Error("Error: At least one command line argument must be present!");
                return ReturnCodes.rcInvalidParameter;
            }

            for (int i = 0; i < argv.Length; i++)
            {
                string param = argv[i].ToLower();
                switch (param)
                {
                    case "check":
                    case "query":
                    case "status":
                        opts.op = Operation.Check;
                        break;
                    case "detect":
                        opts.op = Operation.Detect;
                        break;
                    case "update":
                    case "upgrade":
                        opts.op = Operation.Update;
                        break;
                    case "id":
                    case "list-id":
                    case "id-list":
                        opts.op = Operation.Id;
                        break;
                    case "--version":
                    case "/v":
                    case "-v":
                        opts.op = Operation.Version;
                        return 0;
                    case "--aurora":
                    case "--with-aurora":
                        opts.withAurora = true;
                        break;
                    case "--no-aurora":
                    case "--without-aurora":
                        opts.withAurora = false;
                        break;
                    case "-n":
                    case "/n":
                    case "--newer":
                    case "--auto-get-newer":
                    case "--automatically-get-newer":
                        opts.autoGetNewer = true;
                        break;
                    case "-nn":
                    case "/nn":
                    case "--no-newer":
                    case "--no-auto-get-newer":
                    case "--no-automatically-get-newer":
                        opts.autoGetNewer = false;
                        break;
                    case "/t":
                    case "-t":
                    case "--timeout":
                        if (i + 1 >= argv.Length)
                        {
                            logger.Error("Error: Parameter " + param + " must be followed by an integer value!");
                            return ReturnCodes.rcInvalidParameter;
                        }
                        if (!uint.TryParse(argv[i + 1], out opts.timeout))
                        {
                            logger.Error("Error: Parameter " + param + " must be followed by a non-negative integer value,"
                                + " but '" + argv[i + 1] + "' is not such a value.");
                            return ReturnCodes.rcInvalidParameter;
                        }
                        if (opts.timeout < 120)
                        {
                            opts.timeout = Update.defaultTimeout;
                            logger.Warn("Hint: Specified timeout was less than two minutes / 120 seconds."
                                + " It has been set to " + opts.timeout.ToString() + " seconds intead.");
                        }
                        ++i; //skip next argument, because that is the timeout
                        break;
                    case "--exclude":
                    case "--except":
                    case "-e":
                        if (i + 1 >= argv.Length)
                        {
                            logger.Error("Error: Parameter " + param + " must be followed by a software ID!");
                            return ReturnCodes.rcInvalidParameter;
                        }
                        string id = argv[i + 1];
                        if (string.IsNullOrWhiteSpace(id))
                        {
                            logger.Error("Error: Software ID for parameter " + param + " is invalid!");
                            return ReturnCodes.rcInvalidParameter;
                        }
                        id = id.ToLower();
                        if (opts.excluded.Contains(id))
                        {
                            logger.Error("Error: Software ID " + id + " is already in the exclusion list.");
                            return ReturnCodes.rcInvalidParameter;
                        }
                        opts.excluded.Add(id);
                        ++i; //skip next argument, because that is the ID
                        break;
                    //options for PDF24 Creator
                    case "--pdf24-creator-autoupdate":
                    case "--pdf24-autoupdate":
                        opts.pdf24autoUpdate = true;
                        break;
                    case "--no-pdf24-creator-autoupdate":
                    case "--no-pdf24-autoupdate":
                        opts.pdf24autoUpdate = false;
                        break;
                    case "--pdf24-creator-desktop-icons":
                    case "--pdf24-creator-icons":
                    case "--pdf24-desktop-icons":
                    case "--pdf24-icons":
                        opts.pdf24desktopIcons = true;
                        break;
                    case "--no-pdf24-creator-desktop-icons":
                    case "--no-pdf24-creator-icons":
                    case "--no-pdf24-desktop-icons":
                    case "--no-pdf24-icons":
                        opts.pdf24desktopIcons = false;
                        break;
                    case "--pdf24-creator-fax-printer":
                    case "--pdf24-creator-fax":
                    case "--pdf24-fax-printer":
                    case "--pdf24-fax":
                        opts.pdf24faxPrinter = true;
                        break;
                    case "--no-pdf24-creator-fax-printer":
                    case "--no-pdf24-creator-fax":
                    case "--no-pdf24-fax-printer":
                    case "--no-pdf24-fax":
                        opts.pdf24faxPrinter = false;
                        break;
                    default:
                        logger.Error("Error: " + param + " is not a valid command line option!");
                        return ReturnCodes.rcInvalidParameter;
                } //switch
            } //for
            return 0;
        }

    } //class
} //namespace

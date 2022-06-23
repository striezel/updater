/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2021, 2022  Dirk Stolle

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

using System.Collections.Generic;
using updater.cli;

namespace updater.software
{
    /// <summary>
    /// utility class to list all known software
    /// </summary>
    public class All
    {
        /// <summary>
        /// NLog.Logger for class All
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(All).FullName);


        /// <summary>
        /// Gets a list that contains one instance of each class that implements
        /// the ISoftware interface.
        /// </summary>
        /// <param name="opts">parsed command line options</param>
        /// <returns>Returns a list of all supported softwares.</returns>
        private static List<ISoftware> getUnfiltered(Options opts)
        {
            bool autoGetNewer = opts.autoGetNewer;
            var result = new List<ISoftware>()
            {
                new Audacity(autoGetNewer),
                new Calibre(autoGetNewer),
                new CCleaner(autoGetNewer),
                new CDBurnerXP(autoGetNewer),
                new CMake(autoGetNewer),
                new OpenJDK8(autoGetNewer),
                new OpenJDK11(autoGetNewer),
                new OpenJDK17(autoGetNewer),
                new OpenJRE8(autoGetNewer),
                new OpenJRE11(autoGetNewer),
                new OpenJRE17(autoGetNewer)
            };

            // Firefox (release channel)
            var languages = Firefox.validLanguageCodes();
            foreach (var lang in languages)
            {
                result.Add(new Firefox(lang, autoGetNewer));
            }

            // Firefox ESR
            languages = FirefoxESR.validLanguageCodes();
            foreach (var lang in languages)
            {
                result.Add(new FirefoxESR(lang, autoGetNewer));
            }

            // Firefox Developer Edition
            languages = FirefoxAurora.validLanguageCodes();
            foreach (var lang in languages)
            {
                result.Add(new FirefoxAurora(lang, autoGetNewer));
            }

            result.Add(new FileZilla(autoGetNewer));
            result.Add(new GIMP(autoGetNewer));
            result.Add(new Git(autoGetNewer));
            result.Add(new Inkscape(autoGetNewer));
            result.Add(new KeePass(autoGetNewer));
            result.Add(new LibreOffice(autoGetNewer));
            result.Add(new LibreOfficeHelpPackGerman(autoGetNewer));
            result.Add(new MariaDB_10_5(autoGetNewer));
            result.Add(new MariaDB_10_6(autoGetNewer));
            result.Add(new Mumble(autoGetNewer));
            result.Add(new NodeJS(autoGetNewer));
            result.Add(new NotepadPlusPlus(autoGetNewer));
            result.Add(new Opera(autoGetNewer));
            result.Add(new Pdf24Creator(autoGetNewer, opts.pdf24autoUpdate, opts.pdf24desktopIcons, opts.pdf24faxPrinter));
            result.Add(new Pidgin(autoGetNewer));
            result.Add(new Putty(autoGetNewer));

            // SeaMonkey
            languages = SeaMonkey.validLanguageCodes();
            foreach (var lang in languages)
            {
                result.Add(new SeaMonkey(lang, autoGetNewer));
            }
            
            // old SeaMonkey languages (available until SeaMonkey 2.46 and
            // dropped in SeaMonkey 2.48)
            languages = SeaMonkey246.validLanguageCodes();
            foreach (var lang in languages)
            {
                result.Add(new SeaMonkey246(lang, autoGetNewer));
            }

            result.Add(new SevenZip(autoGetNewer));
            result.Add(new Shotcut(autoGetNewer));
            result.Add(new TeamSpeakClient(autoGetNewer));
            result.Add(new TeamViewer(autoGetNewer));

            // Thunderbird
            languages = Thunderbird.validLanguageCodes();
            foreach (var lang in languages)
            {
                result.Add(new Thunderbird(lang, autoGetNewer));
            }

            // Thunderbird 78 legacy (Farsi + Sinhalese)
            languages = Thunderbird78.validLanguageCodes();
            foreach (var lang in languages)
            {
                result.Add(new Thunderbird78(lang, autoGetNewer));
            }

            result.Add(new Transmission(autoGetNewer));
            result.Add(new TreeSizeFree(autoGetNewer));
            result.Add(new VLC(autoGetNewer));
            result.Add(new WinSCP(autoGetNewer));
            return result;
        }


        /// <summary>
        /// Gets a list that contains one instance of each class that implements
        /// the ISoftware interface, but without the ones in the exclusion list.
        /// </summary>
        /// <param name="opts">parsed command line options</param>
        /// <returns>Returns a list of all supported softwares, minus the ones in the exclusion list.</returns>
        public static List<ISoftware> get(Options opts)
        {
            var result = getUnfiltered(opts);
            if ((null == opts.excluded) || (opts.excluded.Count == 0))
                return result;

            for (int i = 0; i < result.Count; )
            {
                bool removed = false;
                foreach (string id in result[i].id())
                {
                    if (opts.excluded.Contains(id))
                    {
                        // Prevent update of information, it will be removed anyway.
                        result[i].autoGetNewer(false);
                        // Inform user about removed software and remove it.
                        logger.Info("Excluding " + result[i].info().Name + " from software list as requested.");
                        result.RemoveAt(i);
                        removed = true;
                        break;
                    }
                }
                if (!removed)
                    ++i;
            } // for

            return result;
        }
    } // class
} // namespace

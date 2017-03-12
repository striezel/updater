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

using System.Collections.Generic;

namespace updater_cli.software
{
    /// <summary>
    /// utility class to list all known software
    /// </summary>
    public class All
    {
        /// <summary>
        /// gets a list that contains one instance of each class that implements
        /// the ISoftware interface
        /// </summary>
        /// <param name="withAurora">Whether or not Firefox Developer Edition
        /// (aurora channel) shall be included, too. Default is false, because
        /// this increases time of subsequent operations like getting the info()
        /// for every element in the list by quite a bit.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        /// <returns></returns>
        public static List<ISoftware> get(bool autoGetNewer, bool withAurora)
        {
            var result = new List<ISoftware>();
            result.Add(new CCleaner(autoGetNewer));
            result.Add(new CDBurnerXP(autoGetNewer));
            //Firefox (release channel)
            var languages = Firefox.validLanguageCodes();
            foreach (var lang in languages)
            {
                result.Add(new Firefox(lang, autoGetNewer));
            } //foreach
            //Firefox ESR
            languages = FirefoxESR.validLanguageCodes();
            foreach (var lang in languages)
            {
                result.Add(new FirefoxESR(lang, autoGetNewer));
            } //foreach
            if (withAurora)
            {
                //Firefox Developer Edition
                languages = FirefoxAurora.validLanguageCodes();
                foreach (var lang in languages)
                {
                    result.Add(new FirefoxAurora(lang, autoGetNewer));
                } //foreach
            } //if aurora is requested, too
            result.Add(new GIMP(autoGetNewer));
            result.Add(new Inkscape(autoGetNewer));
            result.Add(new KeePass(autoGetNewer));
            result.Add(new LibreOffice(autoGetNewer));
            result.Add(new LibreOfficeHelpPackGerman(autoGetNewer));
            result.Add(new Mumble(autoGetNewer));
            result.Add(new NotepadPlusPlus(autoGetNewer));
            result.Add(new Opera(autoGetNewer));
            result.Add(new Putty(autoGetNewer));
            result.Add(new SevenZip(autoGetNewer));
            //Thunderbird
            languages = Thunderbird.validLanguageCodes();
            foreach (var lang in languages)
            {
                result.Add(new Thunderbird(lang, autoGetNewer));
            } //foreach
            result.Add(new VLC(autoGetNewer));
            result.Add(new WinSCP(autoGetNewer));
            return result;
        }
    } //class
} //namespace

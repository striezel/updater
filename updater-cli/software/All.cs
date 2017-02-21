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
        /// <returns></returns>
        public static List<ISoftware> get(bool withAurora = false)
        {
            var result = new List<ISoftware>();
            result.Add(new CDBurnerXP());
            //Firefox (release channel)
            var languages = Firefox.validLanguageCodes();
            foreach (var lang in languages)
            {
                result.Add(new Firefox(lang));
            } //foreach
            //Firefox ESR
            languages = FirefoxESR.validLanguageCodes();
            foreach (var lang in languages)
            {
                result.Add(new FirefoxESR(lang));
            } //foreach
            if (withAurora)
            {
                //Firefox Developer Edition
                languages = FirefoxAurora.validLanguageCodes();
                foreach (var lang in languages)
                {
                    result.Add(new FirefoxAurora(lang));
                } //foreach
            } //if aurora is requested, too
            result.Add(new KeePass());
            result.Add(new NotepadPlusPlus());
            result.Add(new SevenZip());
            //Thunderbird
            languages = Thunderbird.validLanguageCodes();
            foreach (var lang in languages)
            {
                result.Add(new Thunderbird(lang));
            } //foreach
            result.Add(new WinSCP());
            return result;
        }
    } //class
} //namespace

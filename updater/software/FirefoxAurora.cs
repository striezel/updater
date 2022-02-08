/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022  Dirk Stolle

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
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;
using updater.data;
using updater.versions;

namespace updater.software
{
    /// <summary>
    /// Firefox Developer Edition (i.e. aurora channel)
    /// </summary>
    public class FirefoxAurora : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for FirefoxAurora class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxAurora).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new DateTime(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "98.0b1";

        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox Developer Edition software,
        /// e.g. "de" for German,  "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public FirefoxAurora(string langCode, bool autoGetNewer)
            : base(autoGetNewer)
        {
            if (string.IsNullOrWhiteSpace(langCode))
            {
                logger.Error("The language code must not be null, empty or whitespace!");
                throw new ArgumentNullException("langCode", "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var validCodes = validLanguageCodes();
            if (!validCodes.Contains<string>(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException("langCode", "The string '" + langCode + "' does not represent a valid language code!");
            }
            checksum32Bit = knownChecksums32Bit()[langCode];
            checksum64Bit = knownChecksums64Bit()[langCode];
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/98.0b1/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "4866fa19951e2747b728d8a8e2dc43c288f5f6babd0ee79c4dc791356ab7414d37f770b4c3008a136e448ad4fea4c747f11e6418e56e74b512e39b17f3015492" },
                { "af", "5bd3c28b0bc1a357f71eee88f2bd97786acaf34b57145f61cb2851d262cc403f2268a325fc01e41dec27c9d90ef576e390b9b16126f2d7327af56b931ff6806b" },
                { "an", "6675806c2d02a0c04673cce7067fe7f8b04839c6687d2afe72ab20d6365b81fb9f834e794983304aa7466916fd47e063146b8bbcff4ec4f730f559bb668d81bb" },
                { "ar", "8c45c1a1ca06a98bace8b085897692cb75c2af4da0b41833110804159237af0bc778a86272d75eb8837bea3f837df0be1edf42c7208d0b81834bdd71a57a5119" },
                { "ast", "d99da115abd2306a55d039b68d05289c130701d568c1dd49cc0926e413da37b1ab1285330c51ff8855cfe2f020170ff0fda853868793ae943de516f2b1650bff" },
                { "az", "189b202ec798bbf9d22721beaefe25a6cdafe1ba32a76328a330db53484a73f87d8af65988634727000de7375dc0f17428f7bb4bda43a4ff80c333bc4e17ef70" },
                { "be", "f2232d745bdb4aed19d898f4f63f7dd5e7535633124a4a7546f611b92e305ab28db367fa37c7092fe86e57be6a38eb92091b77bf564d2a19e7bcfd11774227e8" },
                { "bg", "aeff5d69ea7af610f6de49c34435eb9ff1c89674bb9b12a9f0e08d16b1af0ca218ea841bbef2486ca28cb2ab39cf6faffd8c856ffe5e76883fb638abadd01e3e" },
                { "bn", "7312a0a3d9c8c48cf2d41923753a51878d74ae38b90b6ae5b544c004a65d03c4e9c00a8c10e4022874a0ad061d08faf0b29efadf52a4e0dd60745879f7015315" },
                { "br", "99ddea894275c93425dbc9a54736228060146d53af1a09aafa0fb4e0a5bc909ece8110e906f708f630a057e7e8ced24dbe11b9f8ad3c3d7cfbacc448f06b98f7" },
                { "bs", "b2e5bdb788f69c3c9f1d8b05c3027baf2dc60197f28e2003d1cb13c3ea3ae723891fbf517146732fcf54a57b4a31fae206b972d21ed83d3bfdca8567821af4ee" },
                { "ca", "148ecc986e5b0875b9e2294a20199eeec6c54758523d19428ea157107a8c073f3debd7d14379125266a06fdc2b4f93d2e7d6128f947ca731e82dd24380169b51" },
                { "cak", "ea49c907de9e9931c921a53312436334fe5138f2f4b939fae6170df6850e5ccf1f7525dd3cce8fcf73a07b3be09b3056767bc0fc3c29af6f6d258b13b124fe92" },
                { "cs", "72515411a097e67629e11d4a3c02b1728b517ed95b5673a04f5935cd0a4f7e2bbfadf928a07d80ba623fe288df4458953f8626417b6037780d4738f5541e09ce" },
                { "cy", "5cae92b92faaf238e6801b11e10d84944d6dd95a6fdeda8b6e16c6c4fa7c7f90718adeff5de964a08d627e8053796a8a2f287a426e62a4cffe5b3152b5c22282" },
                { "da", "adef9223bcc4bf2c9e1cc613211fd14615900ef4383d963611c1a92042e38291506eef499b83b74863f53f87c62708d808cec357b6b8a90377bdd5945c9e21ca" },
                { "de", "446312f8935da66cf78434dc5f944da3db8e37d95d74c8d74bea00d61296cb5dad929bd23f592187f9c5f5f005fe9952fa53beb59d7ffc9d351906a0e4d2ed4f" },
                { "dsb", "8c540659284b4102f59bf7e02c2e1180b8170ecc7d6ed65d0b6e10de135d566ef7427945041e192a2ccb597fc4ddaed3ce80f87278578ee24bab52a9433f854c" },
                { "el", "3422cfcd13bf746e6d9fc0b60a4b237db79fc466f5f2dab8891d5b1e1294173ed3f32ab610f31c694c4eea76b8e4173b9cae2ee1db8448680b1c124983af1a64" },
                { "en-CA", "bf0d95cab1a0926151127fbc54f8ee65ffcf312bf05ae7a0d00b9ea2edf6dd94e8550d235a14ce195cadf1eed370c56ba7df24a54c275b2fb346db8e6e136b85" },
                { "en-GB", "14a37f0a90ececfe419f805db02db595364f2f8c3d62902e493b0cd4a210434bb05955ce426998c8d7afcdeb14f477436aecf5017f6a015c23d41afadc0188aa" },
                { "en-US", "6332771bc9d384f4cccc336c34e5cd62c765408f33bde6a6fc8a75dc46f61c49446712e2e074745412bcfe2c3238b3d0e64483fba5c0bd17e591adcfa6f4204a" },
                { "eo", "baf241682a280e5aa586b313e30f535eafacb43523216dbb55e01c140990a4ccb4c24871b24e918fdee6d9e17edaa145d34be48674f20bbb1879e705947a9391" },
                { "es-AR", "efa9242353aaab525a181ae3547ca5c321dc684b42dbc0d6d195a1eb81e6819b01804adbd55421aa8de3db1a3fb5ceda9e063fe36ee8260f87b1dfdbe3655676" },
                { "es-CL", "c80557b4c86776e055853fcc7dc656dbfa27169f25238cbe8ba74231f7227370851168f4fe7be30e0ae15d6fb75648f9eee2c6aafc71889127ec9fa54bce6859" },
                { "es-ES", "5d4108e4eeefd219addf9af3c74a8cb07d4ba45ad07d2121ffc085c7c623e741c2f3ee9198a635ee0c50ab55a041373c6cc238d8c16cba45c2f6324cf7a41da6" },
                { "es-MX", "f5b49c6803238c311946a13dab1b55d2440b1004162ea10017282f7361f72ef0c21401c9daec4bdb89304af9551a355779fa7dd6d6429acee69bd0d38dc3e3ae" },
                { "et", "d571b68e359091a955bc29fc069be6c4be667744f711ca2b6bdc4a9ea1a8b4c3b447392bf015e226d042bf4e5e18d83b4e381f32250f630c44a387cbefae42d8" },
                { "eu", "b75f966a43e1916949be65f923a849a9234bda14946564bddf069095547308cc491154683d82792dd81f0c6546f60fe9123ab842c48ac45df681d05986652a3f" },
                { "fa", "8a1f08321e33d7ce3bfaadaba9d87ed500182cfe0a50625be2ea4610eb9d94e3f23a5b657ccdd63981e174ac0683baa84adbc0323134a5f76e5469f8a85d6684" },
                { "ff", "f0316962b3c7110512e2db86acb85163528830a81139e6abd425272324ddb79bf879a16f0b70a3d6875cbbb51d9db355a594754e550dbb907e35702b4f241d82" },
                { "fi", "7f1dcbe25e2ea585ab0eec602261a92112975eda311e1d6491d7d868261386db8ad8d609702b153a22e5525933dee34d079c009cc956210c345debb0fbdd4fb4" },
                { "fr", "0856eb5d4bc546664bef7188143145a1e9c4a9f61dc985a53310557d25292c13a304eb9405a493d5738c9871db0e7d03b1e480fa7afcbe3eb5b51f692f6ebfb8" },
                { "fy-NL", "4843825235d3e6280bf314d6e2ecd774fbdb038b1b3b864feff28ec9d41074ea524ef1300dfc2033bdde338863dacb638bd0c1b9ed2d68956a0ceb07c2470fcb" },
                { "ga-IE", "6a6a117bc7d466b37a42360ab8919918127ce611029665582b73d37be8106f811bc7e5db6f94f7721839d3c120be6a59623795eca81f0fbedf8390e19a0c3871" },
                { "gd", "e5193a923f7c9ed70c1e248c3c3824535d1d5b70b5fcdc978677e4c1300f5f52b41114bab44f3028bfa948d9547a70950ab5432eb5398b11ef3b004a094787f8" },
                { "gl", "cd85794335a54b4adb0d65ca63adb10c32b7913c98c2ee98b717fe82911abdcf3b7621db56c33e3aa00586d13345da16519cdd2a994f64573ddee3377f5bae4a" },
                { "gn", "a88256030e3902b5ecaccd274e4e8294af33ae9c6a71d7910523dacb11dcbc1df150abff83cb8111a648140733f6412d2cf56af928323fe338f67f76c737c49e" },
                { "gu-IN", "002e4835be8ba232b06b63dff75f89d9ac5dcb8353aa1a38feb2a5b19e16edbb1bc2e2922825a62ab181899fea49e40660a158801d85f5cffbb12aff3b1174c5" },
                { "he", "ef6ea1a34abad355fc7a22d4bb39fa853b88b6abba7fb0d0acc0153432bf64a7a092a3553ce284cf10652069f299ee7b8509e5496d170bbdca4f19fbdd999216" },
                { "hi-IN", "950eed2a7901873647447441934864a7b597e7c24869a6cb3f5b81245462217125f205373a708449199805299dacafa918110d8fcc67e71c1468701e4f6774cb" },
                { "hr", "880bac8af4b92fe2ec640a1ec49fc5271db2d06ac9f2db5c8fe267f6aaaa2d8e0f212145d7891dc82c5afbc40c7449c18bbe5953dbeba69bb5f112c85ffa3682" },
                { "hsb", "b3a9a13f72802436c1418a2e914dfbf59843f92a1932200407a32e2682b7deb9147a8b9089deeaae3450732c0788a5cd8226044127b17b2c98b439552e5fe7fd" },
                { "hu", "c3dbc75c5f2719ea7f4d63b5d9a0477ed48fb2db1c9f712919428c7cba8a7afd1c0262e57a08d2b5444c9c4b424b5ab8f8c39d96023880f41a5d670793f7d90e" },
                { "hy-AM", "f9c106de15582c0463749d4b1a64d6a17f262e2858982f0dfc0aa320ad15c9e96086e871c121cde7eb5f44e13ea9df32ee6bade8933876dd45286f7282b41efc" },
                { "ia", "8f9c8750ed4482c0e99ca5642926175a167b7d4a4767292d4a5331f9c4155ffb512555ea3d61599f97028fc0a7e7ed318569dc4d5a7259d33d7ae4261a199232" },
                { "id", "424248ee4a6bcf030aa2d9b7c396d614c8f7cc15d1f48b43527a4fc2f013afb0b06ab153a5542968098628494ff0d8183ad83b7aadfe1d74e36485eac30e96c2" },
                { "is", "5852ba97abea1bca7d553154f0a6807052bcfdebf0ba58c9c461e7fc5c5baffa9dd9563f484762e4356dd4e24d30b5e831b625e9725bcdae2e1a116d21b64621" },
                { "it", "6e7d4cb8b4e6e0643d114a5bd232125b47c664915dcc75af7250ae569a6b9cef59f52abeebc797e81914cb22d50c9925ffea4b9bcedaffe8ba61bd26a7c75533" },
                { "ja", "8e3e26ba8a6f311f2b1d69838346c2fa0aaed80cda1baab4a20c7ea409db74c639403b946f9350ca6ed05f359d89306e0d169c116b9940dfaec56665767464ce" },
                { "ka", "6fd1e93c9b9e6a29c3fcbd3cbc1a18dd8c23b89cbcb1927bb3b00fea632eb6a5ab5637fedda751ab2e4a40e71ecf724a738786fc86e556ae31dafcea55ae46e9" },
                { "kab", "c46c93cefc1ab13206e789e944515964da4efd6d81d342fa97d29f3b0e65b44ad0bb8500683a2749343cae50552dbf47a51fb323e32c71fb44fcbb30555ba475" },
                { "kk", "262dd69b4c6550ea807131bed7b7948f2d4ea564374ccc35e37c51902278b39489a9606e3e67601fc951eb059d5eb87a0b8bde5fd050ef7a9deef40189cac694" },
                { "km", "9761f246cb6da1e5ee204932d6d9ed0039fcccbdb5186577576825725c96fad54237fb7a8c9f262287bd521f430d3100c9823838ca607a316be25a11edcd7d56" },
                { "kn", "fbb9a4db375cac3289c108b5cf447b754a55cbc56cddcff009b12300af5b61c11aaaffba635cabe3bed80c0c5ca8be1aa42bde38de4f19d67e7b51dd5dd161f2" },
                { "ko", "452ecba0356b34097e48e8507067668840884f532d2ee6b6b25988103752806f01ab27194f4ef30880c5dab7722035c570df89bcea161939a921e84422d8108b" },
                { "lij", "df056bf01bc127ad4636af12ddaa67a92f0b9255cae909cf35c9b84392ca4fbe826a78c07bd7b818e917e41ad3af98a66441a8730e91978b044c4d50966f72cb" },
                { "lt", "678f71002ffb500fe13a94ada5d3f2f8247f9d8cc631148c4d60fba5df299df000ff85d61c1aafe891ff3054ed31ca94bbacda167abea19fed96d87569761de5" },
                { "lv", "c8f6e4fcb69e91aff3e041108cf5dc15406304be7254bc2d0776aeffbaba5e17b18a583fc2acebc63374f501de1e6d73618da2de953fd737cc9c484b6a6d4efd" },
                { "mk", "56ce48aad39c7f49ac613d3956d45b049eb8b944db791c2e0107980ea4dd2d9de3aeaaccb9a727d30fa2330ada5397a0c866d14fed59d8270b24d062d8497c0a" },
                { "mr", "d2d7c08f4e556e6f67e86fa431adea97c842b0eb3bc7101c3fd9189168050af1e3c2b2d51117c188a3bebba59969c0e57cd57edc5f7c0c1ee0e129761b01189d" },
                { "ms", "320eeee7503b5d8524beaebcbb26fa57dcdf3afcbb6f1ffe5a0d11be248af42a6840fa8f2b2aa66466d64e18912ed5839f9961f288fe58635c73f83577c47936" },
                { "my", "64694fe788424a70f836954b2a5c81067ce7d0111ff0a73e7220d626f5d4cb84cff9e3d8e8f3218a2a09654686760c8aef4ac687a69f95b638762c477248de9b" },
                { "nb-NO", "8013b12d120845e89c209bdbe0c1d61eae9fb9371f5acaf7b02ec4fd6b7d797bf092e055f4d9394b541668c81e2b14e48926604b707ca0699358a471caf5a9d1" },
                { "ne-NP", "1f24da6231b85ded2aeadd53a7467e7240d42bd88f7d63c4316e8223f1727bf801e54b79df41adadbda5bbb01423e8c34a1e70a68ec80ee9aeae4231a0e3dad0" },
                { "nl", "3f20ed9b5c271909cbf578d6547b1af98bf04b515bdbff0da9b7bdd4d4b8d53e8e35a12562ee31a665c327e663b83c6d3f6fee71d3ae50546af335655063e73e" },
                { "nn-NO", "b85d8a1a6264631870063e569a7c8348a760c8463f58102668a1933b4f1e42e22f42192978cc70d17ce4c07e93c4bc2be462cbc41d409f9993ffcbf61e192c7c" },
                { "oc", "9294aea9e37e81763eb35dc8878bac11639590eddde831d88ea0c4876ddd872587fc2042548da47779d5530d9d95720d11692879a0aa370f8a013f65ec487dd6" },
                { "pa-IN", "0d58fb5a06af10fe43cb3e48f3dae92c1e01b931ebf2ecd5af13e435edb2b100e9fed4e8e46ccbb489082450a921a85bda13bd1d4a9391be68efd3faf7fbe768" },
                { "pl", "a2b90230fdf24080a81d3b235feefb6b7f7aad9e9b9b53f33bdbb84cb42591d514404cfa3d6024c503f7f0b80b4b9eb6da4c219901180304978b2e08a779c465" },
                { "pt-BR", "ff940acb03f42d2210e4d7ef0993ea835b22b7527993c2373fe4e1ba5d618aaa18f48df29372e90c29b6f4884288041c4bf7a3e1fd0eecc3022304a1eb57c709" },
                { "pt-PT", "063e9018581dfa3813a91a91bd21a2cd50c41b378ca5cdde899e0022e944227c3e5ceb18b82734b1ae9eea27cf399a0a9c018ea7bd19b6227948583cec955f9a" },
                { "rm", "a2cfcdf88a034678f4f46720a8138a78208001daa86fd4cefa731bd95daa2a3a98cdaaa4ce4bb45ebea517c6775c60b9fbfc98d6a681627ccf1be737a3cf8270" },
                { "ro", "71a38abb7b7b0ea20edac297abf96662fc7beab0a74936dae264c12cbe4f67b093202544cf5f6cdf891392151248fd61487e6ae55da880c6202fb43b543f716f" },
                { "ru", "768a852cd133722c1322cecca19aba2b35294210b2a1771fa994b607364b593a8d552d06c7eed942e9242e8f5ca1175295c1814693f8712e34177337569b13ac" },
                { "sco", "4257d1ff229c9f3dd04325ace2ba839813c3d808ad5232a367b32495349ef87653207347c0d5b9f6a2bc043e97c9ea224afd2d54b3b7c4b7daa87b04f11a02d6" },
                { "si", "bcd15797773a24a85f4ab4ea6fa79dca2fb56c7cd6a86313e572da38450323edd64920252a86d7c8d72d847ce362157594de6f952b0b2cbff773946a7751c040" },
                { "sk", "b28417bf1a98fc76ad3a53933c1919c5bfd226d25b1ae9540e417e4bd86697e95ec90672124baadd329cb94744c85a4b90879440f0a01e10334dda0bd522ab84" },
                { "sl", "50574c738d9ec13c2cbf07cae60c94f9367a61038bd73b01c377ab96e71661e42209bb8ac3b07ae4be1cb1c873074921dd976a4fd89ebe788c53b10bb0d3f260" },
                { "son", "5c6ac73f4144015b304191e5c93183551186f64272d312ebc4e04551c8f8f70f874fe57b852b4ce475e48d6ef34acdd712dcba4b083e38e757be4b27487e9052" },
                { "sq", "7144fc550674fc9ad762c316a92c5c02c5bb30749e15710356f128b51875ec1fc0ff4ed574542e9897432769bde6e4a79a2dd7efc3c0b821359ad8168f3f18a7" },
                { "sr", "53e07229970401df35c56c06045c115c03af2d552298573edc39a4da0a16e9291f6e075920dff8a7eda462c49f0c9b4e5567bf290cc0d6c6b7e9d2619fa217d5" },
                { "sv-SE", "dbae7b393774f24823da734b0a286b99d3a775284234e133a6b04453f032828e6525bdcd3d1fe86a8f9930c17375984122cda356e45bee11a95f74579843c740" },
                { "szl", "b48d4bfbd5503a306d64babf7cc65205783ab9961e0c16398b5b256b5b6cdc7bb5f74b3662d00ef4cd88c77d40430086ee0008140f946412fd55517a30b46863" },
                { "ta", "376014e1138a563bcf498da7e85719454fdc5167a0ae0da4263d8ece6f5e004cdbaf2b8d6569dd938d50836ded7854778ba852eed88ea2f17e02e574a928d870" },
                { "te", "3e5a66e7fafd24b6bf246e3ae1646c0e4bfb24dbdc427e410209a7d31c77504cb7842574dd9b07fc458bcb228103695fe380282dec90993db568408faee2c086" },
                { "th", "fee57bd6c7411f229fc45969cd3385a341f215981ce47e69c495c279da8a5b2aab94b12c83e31898353358fc28576a5ca5917f03de8c3eb367c72390270aa11a" },
                { "tl", "54797117e1c54186a626ebe3b0c8d3178109ab130da16bd8a37308dd3f93d6f386a6f2e8f13494b0bb4efaf0396763f04ff694bab9e3be945785db9b2d8613aa" },
                { "tr", "db461d162cdc113e33695715f9d8279db5f50d66238d31740d7efcb6bbd668fa2c455ca2ccc6f764c896a2b8576f18cd07cc5fbb874c7c0b198657fb584b58ee" },
                { "trs", "3418c157b8f881e172736196f2cd71273276635c92db76df8b373ef53799cb889f77ddd1675c31d60b5814cab0a55b34a52d22513327579311568fe83cf5855d" },
                { "uk", "97cefbea12d93ed94f3097283812671ab250bcde2ef04b35d79cc6515cc2c9e34b1bf463207d98bca312b424bf57ed7f71935ae5c03d1372645fefb4430470fd" },
                { "ur", "17ed440331c81dd2e4d7ca6f301f3063f4448a1184f2d3c4a11fb385eb7604360107a95a7101b054c1cf32c1637221f3480e191f305f458bbad7eb94c98e7d39" },
                { "uz", "f216b1e1858f1057d1ac125150594669b6ba0600ea4fd1fc4855c0b66594640205bbfc87dcc176490d86311892ea315ed8e6db51037f552ea85e864e7487479a" },
                { "vi", "50dd1f0bcf9977938f60559012a652db4aba9a02117191922fb2b57d302b85f51468dec75d9f53b92ace9709eb1a1fe3e8aef9f891a32cff68151f2f55035f37" },
                { "xh", "d26f2e04337cd1e79ad42bd295d5560522e45662e47b9710920fa48cec847677abe8b4806f48973f67f46035bb12df6c6986803c4fa8e5ad7a5fe167c65cb667" },
                { "zh-CN", "0ee95b1e3ac27befd73f80a4ad176e9e8f365fe1886e2704138418886358d47bc4d23a955aa40feeb5f31728afb0a592d4ef7f2946bc55ffa846eb1ded16e487" },
                { "zh-TW", "c42cb00d3c7f934bab88f5af3dd1b6b59b6e504718b1cf4dd37dcae66a20b790900e7bc3bbd394937fbb36d701bf344418052562b904a566811f0c8f301d07f9" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/98.0b1/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "894dd38cffdf84d7e806f36d27291fda21a05d7922fdb6aee2df2850244218ddcefcef70b67a0c722f7e9922026674e502e885236261ae7e37db488df0c5e5fd" },
                { "af", "f442ffa9b1823703df9fef7cde8ea236410ce8f7630c7e6b005f4e15d2713ffa72aa7be5d588f271984c99bd2ecce34ffaf53519da773168468a78d3c6f9de4d" },
                { "an", "c5e0ef9ecd132d3b7260e6ed87c5098864d1fb415569858ad83fb27e9b893daccb4d9901b84fb61abfd0485502796c023f66f05593a522d81d2cb378e8e87ca5" },
                { "ar", "cc1fa761b8fd6f0158eb1c6db950be76984940c2269fec5a3e7ec75bef7808c240a8c8ccde9b2b18591b1b9841c6549ea3cb577cdd978d060f83098ea1d914ae" },
                { "ast", "a6e9f1c4a29074f8a8161e3bea9eedda98411b0e0676806d2e07736e15a7673aa5e1c7e8968c741ba652e4c3f011732cda40caf99f692abe085f9b0f343d1b99" },
                { "az", "62e09ae5af5188e5d0489afc3c5d26016f5cf5aa1dbdcb54fa3366dee0ebde6d239c6af4a71f344c4b673a47cb52d43e9b6b52d3a5782d5532f27f824c974436" },
                { "be", "1e4e1fd84065a47f27a03c3a678e0b26e56f388758225d0db4d0534800955081fa5364f9216db5bfe55087f0b176ab3075593a60f9191192a586a623578cb6f8" },
                { "bg", "ad246be31f7e1bfa410e9ef32c20c43906cc46665a2d1330ae5fee1373681a2a6bde6c48c3ca1f543ece0a4670642738076f70e4b149bdfcc61f25b757436149" },
                { "bn", "9dda8fd97aecb285b5ed2af2b9edaa2313366eb426765227efce963fb4bf4be14b10b786d23f12d69ce4e2eedcebd37abdc352ec820de91d2a0d3eebf0e26d32" },
                { "br", "c6c153c214a3fd7421f24ecd2a7d25f29f3b01161d1e5c074de8ffc6cc1980d268d4db10d7b493fdd16b8335220df23012145063dc52f5a2ece66facac487998" },
                { "bs", "7db35fd4311e5f82c19707b5a364ba7e3b36d4190b8a88ddb3ece44606fb7b79751a7abaa1b0b7fbcc4274fef1c31841048c4310d51bc7b6bf8427fc5df34031" },
                { "ca", "520aeb14c075af9fe4662cdebcfa3491d9993aba3b9657f08ac4f109c0b1c4f89e0edddaec463e83bf2940751ed0b891fdc5f5d2b8ad7a9a849835adfaf07525" },
                { "cak", "f3b10f28c58deca33e6aa42670dc3ab703e913fc704b9026c38bec521d6f8517489567047caac1423c64a8699fe4c2431796784c8d32ef4cbccd823b400ffbf6" },
                { "cs", "1fff29afd61ed9737a5d6daf92e8861fa8d92356a019b7136d67f21215a885d30082e76db3c8aab5e6770d777f7847679175563e7e076362e925fb927933368a" },
                { "cy", "f252ef84ce8e3f1ca84701cf8a4b7fd9dfaced18daa61ad5c7f4800365fe429fc2987cd0ebc4786ea076958d52d26e272f4909ed44f08596dc4aec1a1f54e30f" },
                { "da", "0f384bae3475fca699500479a1ac22c8ef6ac230b251c7af638f4cdf913707d34875badee74bd667d2ad76dde06e696d000d68f64694a77a5d002b457b6a7ea9" },
                { "de", "3c81d43fec4efdf032b71744c2905792487154f4b12e772fc08ba111e396070509d4968d5dc3d880640a742b793bd2e213a544c8dee6314e179d88f47fbd0be1" },
                { "dsb", "7275ae5fc1e597331488e305d7cb924822da263df69462168986c73e42202d0cafbeae6c551cbea7d7ae20eb4089aa879151d6d45aa8a80b7567e6f3996c2afd" },
                { "el", "670d05b070aed1d26974be127ff6e90d7487879c5abde099d602517dd4c157b004612d93f55f93098a5fedd7546e9db52e3846f4e308169f49b5ce369dbbc8e6" },
                { "en-CA", "53b589c5e65a560ae9aafe23d8dad46cd36ab0efae4bf107ad0303542c36e9d05afdbe55baf0a0afc680d3be50b231533387470ab9903c8b9b604337ff4ae81b" },
                { "en-GB", "d47446267e67b20fbad04d680b96725f21a9aad926806d556115feb725ec23197fdcbcc9e857a6640914c728305a4315555aabd946d28cb7304ace0da42daf44" },
                { "en-US", "f290f228fcc7f3e3979fbf2b52bbea60b1461291195357b22c4a3a07f793091c44901c937e1faa0616a417db1ec8b64a1bf7b46e24a16a256b4648e5bca9d63f" },
                { "eo", "af5b674aa4ee0582fcc55481e9b27df43927be91314a8427ca9fd81e77322c8d8984d24a72d8d3999b8f841343b4a6ae0ceed30e3f77738a9ab56e3a538d95bf" },
                { "es-AR", "8d15f4329019b1c97251e6cd6447b1be7680cbe4898ae5ad591f2e84b9d4fa8bd53351cde9e673311b3f8b2f752465e9febfe13c0eb5c1d94ed4be55c30fbcdc" },
                { "es-CL", "c710811e86623e6ae93ea44c66bebb195d8d3e89948d1f7688c4598aa48a09ccd2dc57b86baa2ed1c739c13b03c6413a8585983333cb568dd604dfdeecb5f580" },
                { "es-ES", "b0828538cb35dd77b912c31df6c6a4af8cee7ac78424f5ae871d8787412371a6905c2f55364a60f17198049e4a3bd5488b5fc8a9a9657112d6e412915081eb9f" },
                { "es-MX", "064b6e2ee046909ede3648f246a8f27205da9da3222623919fa687c369036afa32571715c07090485b5a2969f20ebd6b06119e7ac38454de9cf6107edd9f1ab7" },
                { "et", "47d00241daeb6340b6a5d9d65cf34444b014232b2e2f0ad638f9e38d169ecc9021adfc18a22dde802c49615ad620c3a23e693cc54d97c903c803c61dff98476b" },
                { "eu", "3823920de38666afabc102d505a30ec150b9b71c2a84711d8ad7318f9adb50a214031f113435a16f089d9a754c45897c00183a047fd8eccf74e5e6d1913441af" },
                { "fa", "4e62bfeadb9594649ad019c617c3c33713b8e693a4540449b85be2a1e5372614b5fb27feb7017607aefdf1a96f9aff95c3293afe0949318b97b2c40ae6a68bdb" },
                { "ff", "d455ffc361f2996db316f2a7e3e3e38b763885a3e7b5e0527929030ebd17d1d405292fb4ebd65b9178dd560a3ed32225c4628c13517604e47ab1fc53a3f73a9c" },
                { "fi", "cbc02aadea01d3b94c6b7e6bcadba4dd271ffc288e97aea32e29501ccfcc25c930e496e54b417b83fbe0a4b7f7eab444277a58f397388ccfd0fa19d62c6d428a" },
                { "fr", "80f919f33d3ff2d7cea8de1e3c265e16473e828108581afafbe7b1b46e69c2b2bd9413f89737315c347bb2d98b459afeea699fba1fb19425bf60778a5edf8e27" },
                { "fy-NL", "f002dbbe39afaf7d336144bb66795b0f07ac78ff6b1e17f1020c98f0852146080ceda4f2f560bb448ccb3c9e59f5898d133c5d7ed450b94ba4d8df41809da8fd" },
                { "ga-IE", "f9110dd0d08a3be70cfb5b51fd5b199000e1b296a04293a5463188e5d99ac5d0d8dd9072839d3888c719acf48e63ad8ed689548c74d04ea41f912c62fa497684" },
                { "gd", "b2e9fd94990ed605c0ffc5fefb3ff385db404cb4302ca8bb04da48bd60ef0b353279bcfd84c26cb1acfae261dd304772692ae25a97a1b508ffc1d774f90be23e" },
                { "gl", "59066ff9e3f443f399c0146b4d2fa903c9c3aed08ab06381b494b2f9c4fc709cbacc672ee308382a7aa4432cfc469b88ecbb1df1289fb6c7291b79e69abc61a7" },
                { "gn", "48208d717742d09b4809b20829389a11a1f5995ed3bba6dae48fa48aedb91c0590df1f501dde60abcd0dd2dce04d6370056932c1197be85bc8eb407d12ca34f3" },
                { "gu-IN", "376bd6edba21b7d952f52d730e38844c4121a7676f6d4ff2e9dd69be71281ffc6db0e47049db72860059789db347bb853387294e0dc09efc3cfee21416cb378b" },
                { "he", "2bdea5e87962717f9a5694396c42adbaf020338b22372e278c2547e2728f26c7909efe652899b96daf84177a700ec62816c1207f8eb085ce8d47dd2cf46cfc3f" },
                { "hi-IN", "4018f3249454beaeb0897623f65691a5d009f69ba5622016a9900fb7533c6d74269e2b6502096599d2d41e6cd435cf19b3d5eb832a6f9d4a51429f1f36a3bfcc" },
                { "hr", "e80ffc042cb4f839c701f1fd966e6d2bd3fb21c2b4d3b504f7cf8af3fb12cde6ae5d17dfd96ab135cbe9e3662f00854d42d3832e292d4940a89ffdb511d475bc" },
                { "hsb", "6042c66968ae8caa2b143673c90352ece6e7cfafabe53ede282baaa47225228e2d2a68113bb4f869e6efc819df906011d64926429f0f2ef3530f19363037f738" },
                { "hu", "e65586cec63f617968604aa2aed8fd465f087328202f2d41a038ffcfaf7a2b9f2a2d504960062026322919d45436b8013e3b87b779e53f2f3871935f6fdda86a" },
                { "hy-AM", "4ae70074a2cbc8c0aaf08135d03d2596d7e6bd8a10e4c6a0942a25370dcba07fdf035edf4f1ba44dcf368438f4936248b07ae284c998ebdc5781091c4e4cd741" },
                { "ia", "b61eaa444bca49e963793dcc21ad65425d13589b6f32aeb72778d91dd0a0afcdc377831f2e495bd461eda9296646e17511bcc7df16510de4af6552977a61cd56" },
                { "id", "fb3c8c6a5ef98cb9d3bf40060d855cf4e173cd94199308afbfa2b34fcba659ee8698428d6bd458a22d8bec4b291297b49ebc2224ddb0533a3cea8b366a382703" },
                { "is", "1ba2acd845acf4ec90f8a4420c7a209e3d1bd6618421b4eae0abfe8573fcedfc6ff36d0b44f2536c90a89f8cd25ebab9d2d6c40dcd525a6b6924b88f2103b56a" },
                { "it", "de16c6abe4123d8aa8ddaa2147f7abc55873cf12bc112468936fa005f540896645504843628465cad7aaf93cce3ed3393e317641932f4f9186bedbabf5cb7b84" },
                { "ja", "8f3e1c0114211f141a89331babffa2b47c98bc002fa700c984786b928afa3effe672af85b07ff9c8acd14748e3abd6d6d42c9bd5081080adfbbbbe4fc384a213" },
                { "ka", "a449d557dc82bba57b4f2e957c9b44e33a3242d209521fe7baa7430c347e17f47c5840f698cdb97c41b75126e2ab25a8a686df8d39ae5497c8f4dba864174c53" },
                { "kab", "d86aa16301737ae434ecd7e75ef827c9673f1a98a1c45f91c2acff2ec1134c548869a5db0ee92630ff5f3b25d01bb43ef66dd9c4dc0750de0286ff5dce0978c7" },
                { "kk", "e773940d85d06e538154955d9515261b8f34e9e5c3069774f8face4999c36d47bb0da1afcadfefc649eb0599ac4814af99ebb59c3c2aaac4945a3889a1507ae6" },
                { "km", "5ed13b3870293223a7d08967d3c9b612de019f32f37a3e3ab4b27c7922480122f8339e975df6b7fe961529818e02a1e8e5edb23fccaace684e5e149629a49446" },
                { "kn", "a9ac4c40477fd0e154018f921c0d53a4fb783a45ac6e8b78950ac90f119b47d81cba37632c6a3d1e7a73dc367784655651b8c512e4d6d6e667cf75e59ad0d918" },
                { "ko", "2ba85bd74ceb3e412c8a3b49db8695605af1d9eabff606a613d1d82a27982e6c316954ba5dd7768d8613789b9a10388a3e1a682124a1f0ba862123f913922e08" },
                { "lij", "0b8f0c30ee7690a1853249e8662b951d6697deab61ec32a6d6e136e00b92d0183411d2c924eae4f3873440f43882e00f1fb513a24950b0672c805f0b4a2a2a0d" },
                { "lt", "1f0c833173ea32d6a3f3e569724c4ba2b983ce9a05cb21dcc9eb56d6c45f420d055e07fd8d0afcae579de1bcbddf97cda2d55e8fae6681d861ccd63410c68ef0" },
                { "lv", "22b5dea08d95cb5cdcec72ed5a84cb5986f37e746af447c4499787ccd03641b1bc80a71d771c380f45a35313fc199fa962949d770ee3db409fda489e5080a2e5" },
                { "mk", "3bced139b7b422148da947c74155fc7c40aeaf7ee15fc736a5d720897b598b5768a09320c8090eceaaa214a196a30625c185306c7ac7da921bbb7d9d215c779b" },
                { "mr", "9a1663b31e0c87c0f491b0a0318e65a098b4838cf8e2060eaa1bc93a96779d6e53d34482e162901aaba9f083dd5e6ebf2dcb5a98a58fab460b368533e8e3b1b3" },
                { "ms", "fe6e5931d358d06daf2f496ad06e763b4684e712b97ec97ca8cfcf94c1b9cfbfa05da43511178410418a90f57157e9ac4ed9e917058f47b2c9738d6beb042143" },
                { "my", "1dcb1763309b61d863d2bb7075a0c47c59f6d7aa44e3ec50f2c9d390fa6f5d43dedb546af0d59fd638373d8c3a39c23423d522280d5d78f3168d3c84ade269d8" },
                { "nb-NO", "1009de523e0a3318597b8b267dfdef7a5271c4195bdde29df49806ff929ba0e7c92986a2605469dae4a0d693325226a5ed151190df194b5a7343c0ffc6139d5f" },
                { "ne-NP", "26546a7d707823e8b178b49ecacbc1efa500eeed358b7f96183ba40ee4e7983160fe0b50721ddc00eedce6e5fae0c2cc65cedf324c64cb0e615eda79b2a51e15" },
                { "nl", "f4db8b526d5b8fdfeeb02f6a25ae37f56abdf447e8f7655be4b840ec1b256bf60feff9350c1a038414f88abcfaccb5dc2b2c7ba00da45ead68d602b8da52a0b5" },
                { "nn-NO", "73b382af003383794e18796294c2693e2708af07673ded69a7ce6a526fea8dcfbd38e0f6543d84df60bc6becdf9087a4bff2d902545c5116378634c1ac3a1561" },
                { "oc", "f02f60d37e6d229e614cd2fb0a11f20e25add54c160e31f3357fac83a342474a8a01dd1aeaf9ed97aff5646087ef81a26f1837f750b0e9de1b2e10bf2abaa061" },
                { "pa-IN", "e5ab61d11b3fd537cd3eb99a20d46e469d5ef7a0d01b0eed49e28b062838fd5133d1fae2b2ce8a09f49fa0ed7b5551e72eba5ea71aeabb18c5423d826a6b9195" },
                { "pl", "a3f1ef55c6f28dc61fa0fb1ebe75f60ac1a622e0d14a16a9959f2d1d5e62e82e2113451cced82ef53757665af4d09764446d0e4eb3003d6e49275080ca9448a1" },
                { "pt-BR", "54d78667e8183fd758865e1d8b1e187d21699a9859309180fec295762f958b85fdba3fb13964b5e250b6e1b1c36f620771f8bceed14666a86b1d8b7bcf4171c9" },
                { "pt-PT", "91af5b05e6d85a2721da0a9b42f010d235a698a62b068263f17411aaeaf775d43f6d90c4f159dc86349d013a0508db5ec46d812b260781278b44f88cc761ba41" },
                { "rm", "e069f2769eabf32fea8ee3e7f860a4482e8907b6cd196ba968d92d9029045461a9cd226d7eb5525d9fd1434bdac674516a61f90b3267052b3ba9d429e3f4675e" },
                { "ro", "9a6d1d7bb50484388b5e6bc30c6a367d0de25d1d8a2fc3e08622c22946b851f5d7314da67ce2c9d5a6c476dde08c3ec432dd870560d54025401076f580576a98" },
                { "ru", "7d8cc2c72b2970a64da7f6ddc8e43643bb98bd05a3c05422778a30ad835bf0fb1b1782faecb75ec4cd348c47e774d04ed8387f35f4bb3c3de1ecd3f7a6d042e4" },
                { "sco", "269a28d43de6e2f49d8e8f82c161020f9bff0408b41b737b116f5cb276a0a01195cecd1e0fcee1ce115144c7e7452ef2415a97e20d0d4601b62f682adb766c38" },
                { "si", "7145d3f3a75b33d522a3308fd8ac683deb708126116ec41a3f7df8c05047a07e882a2fe3ee6711b140fab069c30097e04919828aa287cdb07ed460a23f28a874" },
                { "sk", "bc18c8313619d381150b151a8b5bd88c60f43c78ed1c7e167259903a8b5e7fe4e1991c6d20fbb7393311ea44a0637c73a7c430f763132dddbee2a9b5054f2863" },
                { "sl", "19b99b48a7d33dc0e24c4eae6e28c70fd45d9c6383e08e7134a2cf78d38c22b7ae19b874cea10968a18ed1b3f43c2f4338e17746d58cbb661057a920be2f31bc" },
                { "son", "c6416a8d104463709adfb07e6260d2c42917d3652c798d73af134fedd0a8755eb62e9c412d18693af63933049f6299760b8a5aa10762caaa937489466311a482" },
                { "sq", "50d7030033928152b3fb2ad4754429ad1086abddb9bf01389524bb2fb7a4f7258c469b7235972bba9883725e4c08d6644afcd346d545ed126e059ac640d33881" },
                { "sr", "0a79230bed80dd406cac8515866dc58bd858dd075d90a5027e8971ef7dd09e6b4d7628235efa516b04fbef863568398fb828407d517f23c6437f0448fcc42f4f" },
                { "sv-SE", "98bcc3bf817e6c08f368e4a7cba7a944cbe0754569b11f63cf5a6caac14eb9830966a7f08e89b3e89f5765e5121e47abde15f651fa6022815bdf8abd48e3d607" },
                { "szl", "cb8c1d7cc133aae3a9dad8b906c3a087027388b73b2766a6e883316074eb08a73969bd5194b674855ba38fff387dc4fd3f6c624cad8ed06017c02c0584e2c169" },
                { "ta", "2e75f7d46e6a79dbf0abfcf25872b81c295ae87e61c56dbb4cb84dfbf09098654662215f30d95f6083765b3e22bbe78574712297403221f80372e98134288f54" },
                { "te", "4df6a6900f2b5e9bf6d4338b1b5651ae00bddd8750b06a8701de9478b383f374c4fab4a976e2aa2c76c2e6814ef85a669c22efaa505a88dbed0908a4eb5434a9" },
                { "th", "3cf736c7f3f8f410eaa791825365bc4300e0518c038012143e892cd1c85346389b2d30a27abf13641123a5d53f0ceae4f01c3971e35380e92b224eb9eb6fc142" },
                { "tl", "6d0cf167bb4f624a68d594807416d7cf7cc50405b46cc4719262ebfbd4fd8b520b3c27438254169547ecb807f898527a3d9c2da495583d94a43dfa572c61060e" },
                { "tr", "0a28de34e904cf39f1cada9d53859d9494c1e9c13450275331e86429104c2f8f7a8756c4ed990e6d5e035534b5c85e52611a85ea7749b769e646fa2857ddee13" },
                { "trs", "5ceecc02b49c6fd1e7279f552d023188dc1aa730e933d9857425b5b28afa9444d211fac8fa7fbf8ee111d7bb999aa47b3799d4c0ab2207dd7cfae1d256ff97c9" },
                { "uk", "38a57ee7442acf9ea3b681c6d9ef9399020d33652d2978e6548923d8078dff17b34c5eaa02106247399288d9a9723d0d5d4fbdbeaacfc7c9e1b3c90857a349d0" },
                { "ur", "aa8fd93796bac0c04d41936496f5e4c8b4b964841de96d8db3a7da83d5ba591aa9de1d115a1c0b1bc998b01150ed3a98a49215a749f5232586f3eb1db6481c41" },
                { "uz", "8e182b1cafe6c34d603b282572d5c37a863f6b35060c2ed972e14478d7e5a51365aa59af20620d197bf3ad6bd21bccf965ff90b86a7b41fe5cfbfa968f9d5188" },
                { "vi", "7b5aa9dc46a75fd1bfed2fc9d4a3ad827c36eb0d8d01516255d29dbc3275d94826d6bb60144333b6f01b75547708a08dfcd23353ff1fda0683a2478c0dd6242d" },
                { "xh", "9c6fde59d336272d890939ad664231bb575d8465eaa2b18444444e64bb0991bee70cdb4313a420ff7f32a8c7d068664400b9070103600b13010c27842a6e09ed" },
                { "zh-CN", "f223ae6e5bd4ccf5244e0a02c56f65de655d464c31022122078ac8459ba33699e17312f7523c7074a550a527790f087b184bef2ad82d8ef39627a2957194bca1" },
                { "zh-TW", "1cb0e33c6a35756caf701ade9fce57018d3eb66227c2303f3f5a622b39b0036319c2107c9b0b535a001438d51e65d72942f186e641ccefb61f8c1b501419cb4b" }
            };
        }


        /// <summary>
        /// Gets an enumerable collection of valid language codes.
        /// </summary>
        /// <returns>Returns an enumerable collection of valid language codes.</returns>
        public static IEnumerable<string> validLanguageCodes()
        {
            return knownChecksums32Bit().Keys;
        }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("Firefox Developer Edition (" + languageCode + ")",
                currentVersion,
                "^Firefox Developer Edition( [0-9]{2}\\.[0-9]([a-z][0-9])?)? \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Firefox Developer Edition( [0-9]{2}\\.[0-9]([a-z][0-9])?)? \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win32/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win64/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win64/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    signature,
                    "-ms -ma")
                );
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "firefox-aurora", "firefox-aurora-" + languageCode.ToLower() };
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox Developer Edition.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://ftp.mozilla.org/pub/devedition/releases/";

            string htmlContent = null;
            using (var client = new WebClient())
            {
                try
                {
                    htmlContent = client.DownloadString(url);
                }
                catch (Exception ex)
                {
                    logger.Warn("Error while looking for newer Firefox Developer Edition version: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } // using

            // HTML source contains something like "<a href="/pub/devedition/releases/54.0b11/">54.0b11/</a>"
            // for every version. We just collect them all and look for the newest version.
            List<QuartetAurora> versions = new List<QuartetAurora>();
            Regex regEx = new Regex("<a href=\"/pub/devedition/releases/([0-9]+\\.[0-9]+[a-z][0-9]+)/\">([0-9]+\\.[0-9]+[a-z][0-9]+)/</a>");
            MatchCollection matches = regEx.Matches(htmlContent);
            foreach (Match match in matches)
            {
                if (match.Success)
                {
                    versions.Add(new QuartetAurora(match.Groups[1].Value));
                }
            } // foreach
            versions.Sort();
            if (versions.Count > 0)
            {
                return versions[versions.Count - 1].full();
            }
            else
                return null;
        }


        /// <summary>
        /// Tries to get the checksums of the newer version.
        /// </summary>
        /// <returns>Returns a string array containing the checksums for 32 bit and 64 bit (in that order), if successful.
        /// Returns null, if an error occurred.</returns>
        private string[] determineNewestChecksums(string newerVersion)
        {
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            /* Checksums are found in a file like
             * https://ftp.mozilla.org/pub/devedition/releases/60.0b9/SHA512SUMS
             * Common lines look like
             * "7d2caf5e18....2aa76f2  win64/en-GB/Firefox Setup 60.0b9.exe"
             */

            logger.Debug("Determining newest checksums of Firefox Developer Edition (" + languageCode + ")...");
            string sha512SumsContent = null;
            if (!string.IsNullOrWhiteSpace(checksumsText) && (newerVersion == currentVersion))
            {
                // Use text from earlier request.
                sha512SumsContent = checksumsText;
            }
            else
            {
                // Get file content from Mozilla server.
                string url = "https://ftp.mozilla.org/pub/devedition/releases/" + newerVersion + "/SHA512SUMS";
                using (var client = new WebClient())
                {
                    try
                    {
                        sha512SumsContent = client.DownloadString(url);
                        if (newerVersion == currentVersion)
                        {
                            checksumsText = sha512SumsContent;
                        }
                    }
                    catch (Exception ex)
                    {
                        logger.Warn("Exception occurred while checking for newer"
                            + " version of Firefox Developer Edition (" + languageCode + "): " + ex.Message);
                        return null;
                    }
                    client.Dispose();
                } // using
            } // else
            if (newerVersion == currentVersion)
            {
                if (cs64 == null || cs32 == null)
                {
                    fillChecksumDictionaries();
                }
                if (cs64 != null && cs32 != null && cs32.ContainsKey(languageCode) && cs64.ContainsKey(languageCode))
                {
                    return new string[2] { cs32[languageCode], cs64[languageCode] };
                }
            }
            var sums = new List<string>();
            foreach (var bits in new string[] { "32", "64" })
            {
                // look for line with the correct data
                Regex reChecksum = new Regex("[0-9a-f]{128}  win" + bits + "/" + languageCode.Replace("-", "\\-")
                    + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
                Match matchChecksum = reChecksum.Match(sha512SumsContent);
                if (!matchChecksum.Success)
                    return null;
                // checksum is the first 128 characters of the match
                sums.Add(matchChecksum.Value.Substring(0, 128));
            } // foreach
            // return list as array
            return sums.ToArray();
        }


        /// <summary>
        /// Takes the plain text from the checksum file (if already present) and extracts checksums from that file into a dictionary.
        /// </summary>
        private void fillChecksumDictionaries()
        {
            if (!string.IsNullOrWhiteSpace(checksumsText))
            {
                if ((null == cs32) || (cs32.Count == 0))
                {
                    // look for lines with language code and version for 32 bit
                    Regex reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs32 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum32Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value.Substring(136).Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs32.Add(language, matches[i].Value.Substring(0, 128));
                    }
                }

                if ((null == cs64) || (cs64.Count == 0))
                {
                    // look for line with the correct language code and version for 64 bit
                    Regex reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs64 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum64Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value.Substring(136).Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs64.Add(language, matches[i].Value.Substring(0, 128));
                    }
                }
            }
        }

        /// <summary>
        /// Determines whether or not the method searchForNewer() is implemented.
        /// </summary>
        /// <returns>Returns true, if searchForNewer() is implemented for that
        /// class. Returns false, if not. Calling searchForNewer() may throw an
        /// exception in the later case.</returns>
        public override bool implementsSearchForNewer()
        {
            return true;
        }


        /// <summary>
        /// Looks for newer versions of the software than the currently known version.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the information
        /// that was retrieved from the net.</returns>
        public override AvailableSoftware searchForNewer()
        {
            logger.Info("Searching for newer version of Firefox Developer Edition (" + languageCode + ")...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            // If versions match, we can return the current information.
            var currentInfo = knownInfo();
            if (newerVersion == currentInfo.newestVersion)
                // fallback to known information
                return currentInfo;
            string[] newerChecksums = determineNewestChecksums(newerVersion);
            if ((null == newerChecksums) || (newerChecksums.Length != 2)
                || string.IsNullOrWhiteSpace(newerChecksums[0])
                || string.IsNullOrWhiteSpace(newerChecksums[1]))
                // fallback to known information
                return null;
            // replace all stuff
            string oldVersion = currentInfo.newestVersion;
            currentInfo.newestVersion = newerVersion;
            currentInfo.install32Bit.downloadUrl = currentInfo.install32Bit.downloadUrl.Replace(oldVersion, newerVersion);
            currentInfo.install32Bit.checksum = newerChecksums[0];
            currentInfo.install64Bit.downloadUrl = currentInfo.install64Bit.downloadUrl.Replace(oldVersion, newerVersion);
            currentInfo.install64Bit.checksum = newerChecksums[1];
            return currentInfo;
        }


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be updated while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            return new List<string>();
        }


        /// <summary>
        /// language code for the Firefox Developer Edition version
        /// </summary>
        private readonly string languageCode;


        /// <summary>
        /// checksum for the 32 bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64 bit installer
        /// </summary>
        private readonly string checksum64Bit;


        /// <summary>
        /// static variable that contains the text from the checksums file
        /// </summary>
        private static string checksumsText = null;

        /// <summary>
        /// dictionary of known checksums for 32 bit versions (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs32 = null;

        /// <summary>
        /// dictionary of known checksums for 64 bit version (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs64 = null;
    } // class
} // namespace

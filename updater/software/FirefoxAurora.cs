/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022, 2023, 2024  Dirk Stolle

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
        /// publisher name for signed executables of Firefox Aurora
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "131.0b5";

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
                throw new ArgumentNullException(nameof(langCode), "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var validCodes = validLanguageCodes();
            if (!validCodes.Contains(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
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
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/131.0b5/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "dfdca22a49f8bdc6fd1572594e65f24797513f0417216422957f85ab5f9a6f11d0f7640a0a6156de9035a8393f215363844b5af563bc6439accd995009ec8da6" },
                { "af", "7dc60d8454184ee5e3c5916b5e4a03a0a350c7580c1450b175a5f25f0fd0a102b8ce3b52691f3d5bfe64a474b058aa587ab980add04e0c3b41c5cfc8b2c53f9b" },
                { "an", "8cb84e24ec9f355c62614cee9c89ca9762b683a8e54dc99a5d9dede79c0b7701442562034391849c3e58cad0ac5f90e8e4e8293bdc4757c945e18b38313b3d64" },
                { "ar", "1c312cba8d94c2cfea7e3f00f155851cb0c07cc33d2462af59cb2165ae293ce313e0ff9259547e4d7474089e50f05da16857e3b02594ccb0468e45e7071801a3" },
                { "ast", "e0f34c7da5638b2dcd07c0bb99d847ba1371635bd80ea8d87389ea9ebe45a3814defdd6fd18d6564555df9dcf16de6b094d028504afa7eb3eabf9d62796cb5e2" },
                { "az", "2cda5cad0ec1694d2b9e92895ef8750277ed606c5ba3564ac45b03ba4dfdff375553e761b01eb12af688a1eb91dae9b45ff1826ba71f3d4c7945272ccb54766a" },
                { "be", "152fedd978bd3d78f6607f3f77ca0748cf8b02ce24f10aab7407e1091c414c65f16b3bb764e6df29ac2eedbdcaa873399ac8288119fb05cd70fa2de52b312839" },
                { "bg", "4ba8cb199ad6989fd333eec38c99a4e2d4ed578af077b8f72de2021fa8fe8ba89130c1dfbf48ec541eaa589bc4431cb75a4197ee9782177943428d8fba414592" },
                { "bn", "c42f455cf04d64af741e97fc452224c3aca1d2c7ab081d5f3e7e06a7a5e68bade4914116cc4404e8386489bd6ab8bff37ba554359f00537ffea16165af26abc0" },
                { "br", "6f520baa889f0f59b8d62fa8d416d9b71f65e39bc64cd8ac5980c08dd4face4379e4298ecf3178e3a4dbe4865a1a27bdc2dbb1cd7a1908031a476e2d700016b1" },
                { "bs", "160f5af9d9693912ce28e4b6b1f511acb25d011c18e5fa2db6a50d0cffe41e14baf91eb68d592b9f30e4e874cfdac0c569673f0b7024f2c254067e9a94150ffb" },
                { "ca", "da8428b74ef794e904db48c681d67263bf5f400f09334620ae9d68ff253d944ae3a79169321097d3a840139eb0eb3fd21bf9ce8581ed17c7a3119e1fd8c02260" },
                { "cak", "743c1379850d4b2e7684a9037b6cb88d3391770e7c9794cb62a06bc44fcdd582b9df8516be42090fa0395d58503cc955d42001ec6d4be86cb36e5cb6e204db6c" },
                { "cs", "d746cf356142d6461a186e6657fb8b5abecf5f1945c33dd513aa4bdcf48127f49061822c707ce92769bea67662c20b838d915ce2b718fc58ccd2b58f2467d808" },
                { "cy", "3c3546914d1a1f2147eda8de34820aa646bb3603860c9341471940876460e55f1880e8c6a53457a14089a06d7882aca41e404ba1507db0ef30d35dc76c07869f" },
                { "da", "f1b81d85e0a2fd0296f048721c52769cfc1009963db7df81262c584f8bdd89b7424c60055791d8c8969da6e76a8420413a9591f1a2f1e9e96702836b83de7db5" },
                { "de", "98037fc30da550e7f2b8d5b0fb489dcd8886d82d6f7e39fcdfad4958ed2632a8a6aec9065171179df9d5b57547d28a6ea1b3788e72375ceaacdc0012fe603b48" },
                { "dsb", "77653fbb6aa982e7981dedf1bc70cb54b8e6525746a4fb3dbf9bdc47dfdb84cab725a5835e221b08acab17ac124cb816d95742ba4980de49962f7c5f8ec12e52" },
                { "el", "1d3c7f000c11eba30d7a191b4eb5d374289e33faf7c67866d4001c3f61eef358671600934f4b445ef9e4899cee9862a431f6214a5ce5a8c81538c0464d99b158" },
                { "en-CA", "a0fafdccbb903499df895b4ec9fa69994e5728c9f224fed357fd8033e0b6365e3f20d56d23f53599df725e634dcc8952f19917be111e487366ed179e080e72f7" },
                { "en-GB", "ef5eb4c8044073bcec2cd0fef06e418bf0d7a936b04c1753a7aa20f75b314bceedf83fbca4d682f91a6124bee5e80930cdea5707057abd0a1094d8fb84221da2" },
                { "en-US", "f16047159d3a01ac323ad6b43e6a5a4975fa28b65ddac9192144f3cee1cc31d3b3bf190a403bd242f864547ccceb528139f7bae8267bfb8ec54b835914de808e" },
                { "eo", "358395709f337887d6528166bd7d4e712b5fcc3d33a48dae37ba936289f8152a25f87cf466b5b1368ef39907ea24e4e21362a33efed7e188838131f137bb8d2d" },
                { "es-AR", "0c708011c6e79817d504b4ee932ca9373df30de284cc3dd8a5855150cd40dcaf7e24b5f3cf2957127735b924ba9d56ba4fc250ba521464b834c4d7a072339ee8" },
                { "es-CL", "09d315715b2c4bf73927a605908992990b28b9e316a9c24eb8c0dd6e433819ded5a6e8740a053a7e3ba25da6e600cfbb9b7247786ad178850571d2e1107584f9" },
                { "es-ES", "1db1307a9bef25b077326a103a03e3c112f9a1cad650ce6921c72983f30927a700120de978b3046f2f5fdc25ce1ab2b47c6685bb740c4278a62fdc94366e7e6a" },
                { "es-MX", "320c6ec25d6e2cdeaf1c949f21335855ce94bf974a954e757b33b7b649431b1b23996c7acfddac6f6efeeca2ca203ef51085028b3468ebd8c6d52433ca6f5891" },
                { "et", "92916941b9d2dcd2c5b02238d332aff433db1708079b5d8b24c72d388162609c8eed91957e217f4e7491fddac7d17f17735cb8a78f3ae0ac278242ba674037f8" },
                { "eu", "40391a4031d2bc07ab2cda61bec985b8e29c67f1ec786a2a494ac1125624fd920f35d3008a569b02debba472f0749e7080a95490796fb07faa896a5ffb818baa" },
                { "fa", "6f8f382aabc0a6e058ea5085f9cbbac5cb540f5a26ba1076d459e9bee03d9b280ef24318fddb5f516f191278b8d0cbbd127a86f891b11301db3588e4e6573934" },
                { "ff", "ec161767399d4570a68431076c04ffcb5dc33db0cfedac774485bd4d7d8b6f5dc81cde6af8007f7c9b8ac3d435bb4085cbb4637faaa0ac49a2f37223f272859f" },
                { "fi", "a4488ad84a4f3a50c9aa5105b2346faedf1d7df68750cbe441d9096869516723deb81a464ef3d89f6c5100223d6e29059fba95993e65faa97087233c857074f8" },
                { "fr", "5d770cadcc83c34f7882232f19ca209598153ce15198be9a911dc06cae96f84b191e1590923b1b57cc51db24b3e2ba71f2341449f523fcd5c7a1f986a884e0de" },
                { "fur", "8b1e1cc74b403536ed9c14b13c513992901ddb2fbe6f731d1299c1c252cd7a8815fd39ea6fe550f2120f9b520eb547d2030e8ea18f89e7470f188d72dab0ae43" },
                { "fy-NL", "165e24702b67bb68dae6243d0fca3f3158599d94874b6081f0edf7e72530dae9df2d68532818a24f7e69b7132f9d5d6b6e02ee9fe738073f6dd5740491120dc2" },
                { "ga-IE", "370d5faf5486dc8573b9304f20e5cdb6ca8f7c9c2c35f51670e1b562d6ae688644f6f259bd3aa4a29ad4641e791198bb3f3c14a58ccd7d0372fbbb715f508b49" },
                { "gd", "9a05a62ee1a7bb8f0077d3062602e8c428fd42119f9ca35b8cf7e5fc5ba58305b980d09104b5788c2802b1d6df064dafb31a53c505617eb415bb01c100b7f176" },
                { "gl", "58ee5525ee2bc5a3c07dcc73ce5b21d794161eaa72fbb8d8410aa22a50c76a40bb0eb4f8d77bb7e7446b1749ff2f82efc5a8772c5c66fd6176fcb98ea63788cc" },
                { "gn", "faedb58726ec8a7a5040770e49897ae27c5ff285b8d268d951afb6447fcc7c32ae872150850103c856d4cbfb21f324660caf846767a4be8a363c03ab3d20af7f" },
                { "gu-IN", "3d9bc56ca0fbbfde4e4576eb3128033aabe06311717e529648883f05fc07de273ecc7eefb6e0d0b8943d42840d0be4c29dc8ccf4a833ed25b30564c3deb2cd48" },
                { "he", "9c9da0364455ad1011c76382a80ad6d201ce02eed730ba9067ed5974de7152517c81f66f2b391781395d2d5212e5e0dc3859f930846271234b4d8a51cf78a67a" },
                { "hi-IN", "ff2204e2d5df768efc239cdb3328e39f2ba8d9e4a2eb2252b3f4c5ec6f883109f98ba5f4a668ce38184439a1a6f36bbd7a6538e70adb2a8285d5cf482f6db127" },
                { "hr", "aa3b61d58fec5db035dbb87ea373331826bcdfb29b9d3098df16ef5d7bf0d1fd6a9b27cb223df0d00555644b1ce89ead901046302181add2db5eb556157238c8" },
                { "hsb", "aa7cc1e1c33c593d55c2fdae6f27722f7eb2a632ffa112a97af2589c178e6c54ef7bbff9d84c90d3b193c1cbd6927393a588dd8d40765cf558003f89fcafac55" },
                { "hu", "962c49c47604a189b2caf02c1023f5aa9d975e74ef8a74fb51b9f531a824680d3d510fee74ec5e5af128a186d22fed915154bc9b17fa6ae8ec96a8a1c59e12d6" },
                { "hy-AM", "8d62cb10e8d23d897a6d3307a528c1cab3579ca2e2de7405e71719fd8daea2ecba0c76efae43db5fd881ee8020d1172725aae318177583947bced5dff28e9963" },
                { "ia", "72a726e8e3267f1b21846d0fdce332460081c65f62d1cee73993dd329a10d56fe302b53c754af392d1713b49b92b7e9b3b5acb960bc992df35ac1b261a50a263" },
                { "id", "5e4d6dbb05441001b87d47888fa9ff6ded957305a8707fc3dbdaf562adf95ac164e6633ae16532af73052ef5038765c1ace1e58561d7e5786740ad2b0f77bf3f" },
                { "is", "c70f1405919b3d480d55b7719c3487b7d5ba3e8f9ff4a1a704c793151883c89d70b0ac120524226e83ed46b8467f2528f5814ed7cbd8f1b804dd73501068fbc8" },
                { "it", "94f4b8707e765156d389eadb1aab915606aa7ba9f66cc2345cfa34cd7bc7583e0cc78714d48454056286e034ee6a1f79148b386f557bba2f6f8885e520ccf7a6" },
                { "ja", "9b0d0191b3a2cfc5502aed1b97e4d90e15a2eeba8525bc8e59bc2dbd693c1d9194fbddff3c961badfcf4e83868827bce6ee1f05d7d0550c0b6c3fc9700e78084" },
                { "ka", "5dffd59a6f43f0047b5e0bcd41e474e462fd9262769b0a4051facefefc4a207a817593fec44c7b79218069b937acf3cc933ee0279c44ea56fcf18506a99e61ea" },
                { "kab", "5c06aa5b34071fe957b86efbf9f5c092fc94d0a640bfba2f49a55507f3cc6625154e8df69ac701275d59e463a04de21da6567b1133b4b6bff26ed38cd873fe50" },
                { "kk", "e5740afb0806ba471926c515fa0a078835564de664cc9313193980d1600a09f9400ca53c3929e8d869c4df9b730d08bf384d7adf973637b210c562b0bf651020" },
                { "km", "f110b5099237e97fb065b1aa8760a4f7603fb5f22e807007f5b9ec46cc6566fe43bfad946737d14b055f6c39d52c63a2309ccb97e6b28f4026eacedae3e20490" },
                { "kn", "348f0c300b8f6d18314775cd3a0022440b046e9eb651892f7af0b6014d934a5ea688e08aaa511d35e4b5c974fdaec0f8034cbfcb916a19830015ca44defb92b0" },
                { "ko", "24444d3bc755f3ffa583bd78036be672796340f28f2d80d8d083743756f2b058691a89df06929f8d18e714182af31628422597f4d731051044d7ad3970c056ea" },
                { "lij", "5516d5ae8e09a6655fdc9b7aa5239382e28ac3a0e7fe156ca63d97f5cf0fb9368e5848e805586e0e1f7ffdac95c9b9c058d928be555c29d54721170444c3d455" },
                { "lt", "92dc337b1151ba565cb97163d969fbf98b164f378babd82cd082e771f3a04c57e8040e5e51340bdb7c6b35b087f8383601fbe03b269bb0a1e353a05dd04efc45" },
                { "lv", "e8939d08d237c0e4f31d0b5d7ab08b63493cb692b755a8a3b6a4ee6c1fe8c2879eb2815d72201b6d9e958b5b1218ea9d9d01fd20c36d10b592e47716d08d5b75" },
                { "mk", "5d0986ffaa087dcd7500d0c65de22cca02a415257f7a4238d80b86ff65b98aec1afa25fc18411c53184d037a9abd560ef59920307512db069eb351660f0f7e02" },
                { "mr", "833d89bf136b4299c22b0a7a46b4dfc091a8e267f4180ddc763ce28cce2893aec67b2c37365f855e15ef3d20d3ede335ce4d253e7be6831511727cd6f18de6cb" },
                { "ms", "f81bf6f1fb5cfc34171452b190e65ddeea022f43cd3500ce0752552d88c5172e2bd5aa09a12550810766d247ae5e6872919a3c7bcb147cb064eee995b157a813" },
                { "my", "cd03b90499463e34cc6694433608dfb0dcb86e2b3527eb3b685da08bc86a32ef17fd3e754c7d6a3cbe89818df0bf0e25318443b647e5281e22f409b54379a3d7" },
                { "nb-NO", "794c061e6cb6ec6b688004c133001bbde8c934a9d6a6bfa876fbad044a427af55fbb34f2d6afa02f09a692fda98a919bc41284cf3c898bc2e15988c23f58019e" },
                { "ne-NP", "ae425e4a67d822b01d28e4afd5992e1f44cc7af3f8f7360f2f2c4b2ff1cab4b91ae5fff5504212796a89731acbf2f83b070d9d82effac2439caa0167fdcf6907" },
                { "nl", "b0f330b775d9a1b32c6618cb40628cc2a7515bc60d7a8b4cd0a8307b9bfb7c51739bc46c19ad75dc3f2c30ec3c6ac0239cc60c19a72121b20edc79b984f11942" },
                { "nn-NO", "4e51eafbdd4540c507677cc899db2835f67722f205bc8910da6166cf6425a46daeb7cf481234170ea0c48fa6b76c4e9878316d58cad5a467530c8706853fec57" },
                { "oc", "9496eb93eb08b1470a8c4f09cccfbec11f0ed54702594c0d1c7456081daf395412017a10e27e8687ae45decd43f0156252248d1fdb0d1cb49e2b86ac06612923" },
                { "pa-IN", "60cffc5412a0165f805971a8d20e023b53cbf0275c9e04a09335502347b6fee363466a628c99ba57e50f4c6e3efd9efe1c6be4583175a2b572c42d0399dc23e7" },
                { "pl", "653b150c7f62ba9da107f060c1961aa5b628baaf70e655c6b1cc80b6a22f75244bbe16e2ddd41e6a2f34cf7de49a6158a3c0ca76a3532148e36386a8d098613b" },
                { "pt-BR", "de858054dbf083e93b658dc1e04dbfd4a367f8fcdace230251b630cfd2dfedfbf1c7030d356d986b14b8b6622649873acb8cb2b4534ed43b1a58121090d96de0" },
                { "pt-PT", "f907e05d1e0ceabff84bffbc93dc197a34af1757f693511c772b298aedbb2d48965b162046279986e115c7120737e49f421069993a61611d1834602ec4a8c8ba" },
                { "rm", "a29180b69947a90bc140644289f24d43e4b23c4a2c4c2d571af17ffaff96bc78536892ce2110be77005863b6fac83813270c08b90f4fc32d6c33dd6c4afb8587" },
                { "ro", "4525ada484c85dc7396b815e73026178b0cc9a875630d9c753f9e934c82e3dc5ef577f0dd73aac32dc272eb3d39810830f484b127b59cf56201c7553a889b5f2" },
                { "ru", "b38d3766d27ad88de52c13b6edd255e41ebd109973821fe6b8ff76dbf4f144471e7c1eba80b8c9963d59286e5dc70202fd7f89721fa6df16edf198ba26630629" },
                { "sat", "3bf1f35075bafc6e0eaf86c032c8022e37e1c278b351c9021dce68ddb6ea6f76c79aeb079d0cf8329c88cb8b78def750e4b5fb169d3c3316519f99d02155eaf6" },
                { "sc", "03527dce979fb91d1a6e5b6eb7b272e436778cd28ddccf28ffb43e27aaef4b1e1d489f8831540b3c283faced18fb020cebe61b425f0d4e0e280d26e89944ec02" },
                { "sco", "b86ff6b7e1fdbf6042fcff9783cbfc0902c992390dec94d6935ced5a90a81cc10438549cf111f91151ae5605197ecb39b3fba7a04de061150eabe7dcabbf7e84" },
                { "si", "50e9b4c4368712f53603dd596c2a289e3d232168f46a91db41fe7726a183a69e966826bea6cc6ab342aa4d8fe2a7d31fcf1cbaf02211089f1b3408d6b69a3910" },
                { "sk", "e674a9a63dbc31bcc584b933fad4713d4fa7767b849b17afd566b6850a6abbcfbd33dceb664d248a1cef959ed70e47765edc316ab1c998e06cc6b30d5dd7a3c0" },
                { "skr", "683f11b96ef86ef7fcfe29dab5593f8d3498bd0cfe8b4d9004f959f6d3a4d74c9b8e43644377b9b154f286e34090b427a3421b0dceaebceeb21c6dfec3e8d9ca" },
                { "sl", "b76edc9d3d296ca0b0888c0dfdd550e28d6f163156dc6a6f445327f33d403dc7d55429e6f55611649b51b290774ae23807a309ab18c3c1d8a44a784b5c17db26" },
                { "son", "ecb793ca7560b6a65676d8ddc368c05ed1843c5e3cd80b3af001a0f846dd9d55ab1e386aca9446a19bcc56c125ed8d0e71c3a0ebf317de774913378abffab3cc" },
                { "sq", "e1bea07606981ad3bf335b4931b87fd9995293fb47b88dc71439551c48ddb535af130b954807d994290248b121a35b6f55ccb7b2f692e6e9e4284f404ed4334c" },
                { "sr", "3fb9b84efa462caa328eb7e4dace26b1e64826ae503c75939886ab9f38154a2adb6dea7f85ff85286496dc2b4f31e399a5cd708e7fc0da3373603fc4070ed636" },
                { "sv-SE", "57b7b845e96f4b87135234c78d121e90f9dad119dda01b4ab00be637ece0e9f21f51ec0b9d4aeb68dbcde3057c43fa57e494df8f66081525df9cc73e426e1f54" },
                { "szl", "a49a02b84b243e7db2427e9d36ede146dd4c83e7b56382e9f90378f3e0ec28d4da4d3edf77be4b56b0f7fcfdc2789ec30712d9362a1853970215a4d642124186" },
                { "ta", "0200b2509c2826f3bfbffc3b41337604999f09e70ff3244530dbdd5d97ea00c0ac0605fa272ef8abe505d47ef47e9b552dc85b3ab6de08dc91446899ddb519dd" },
                { "te", "c0aa1c57b58c560e4136caec8ad851464d59ea227ab12f087b7563ea315536e2531412b621d6d8e8f2a92fe6ed5d0a8c592926ee62e24f7401de1a376333c08d" },
                { "tg", "c0b50ce541d5384cc6d2ddf9c072729eba599b9e1cfdd5c0ca14b2ce7b5bc5fa3392e176abf08731425c6bd49eb3d0d07a9bb29940adf7a5f1deea5a709fa125" },
                { "th", "e0d025023ae030ea030d56a03a987d0ecbdc2c8b85078ec9deb184543e02bfb796f488621b72be175a019f000e5e48acdea44dbb35729bb311e5208907c112ec" },
                { "tl", "6565ddbf26e86151ddd9c3a9d585c3b0b1a3a7839eb58f5f2ab18c0833c2f8eab6adb58735c6016fd52d2870dc5b23365dc93570fa7b9358b9138df90d32c31f" },
                { "tr", "b511961325e5c4eab5087af2c3862ae5e1da8cc3ea1d0bbc1099a4f4d0ac2ac02329adf77d69458656be0b44a3e9b776019afc8606efbb7145dc3c39d682e1fe" },
                { "trs", "6ccbd476fd66d98eb926d95feb442bf0d71672d1061a144d172a5a6c33a45fc3bb6bc65031427315799287bfb70eb2eebd6db78e85142a9ed8edf7e96b61a588" },
                { "uk", "b83ccdf15272a41d541350edc5c794bce6d368f41e8e2db5cc4f4deeb5f75526994025641ff495f4bc4a964414d3acfc8a7b05b86bb243fc5a6d21c4aae6daab" },
                { "ur", "621e0bac354924d66827218c0ca27fc7f525fa1fdccee60fd0549a3b32f4a9155cfb64b9162f32e5f548cc99f75095b0496991270d4673b18ab48d721a3871cd" },
                { "uz", "6d210ef220bbb7db4e525888e57b49072dd8d7a7b678733a1baec0d287ce96b03358fd02ce40921d8dc03f616cae88faea6b055cf39f4fd32e896b1e827e0a60" },
                { "vi", "255033846461a92707b281463d97927cd6770d7537f75975d5eaeddb97c05519815569e27365cdaadef53040b24128935531c8c3819f4acbd5de11317a1cba07" },
                { "xh", "04efbd5b4486541fc8b0c827e87bbcf202a514fd97351648d88a27d61591a675302dbca73da48236d227a68337726850622c1393b22c3cb7afb867a06ca40043" },
                { "zh-CN", "518f6f8b04134a37ed26fc615bce9eea080bc5fdc58fa0d930110d187860a3cb853406ea32eff1b0f6f016f45519b7d31e11d8c7ba2997e42bb1d96c3c06bc55" },
                { "zh-TW", "462c44af49e190570f9cafdcedfe812e32e8506e4fcd3e724b5a0fa680aedc016ea7c3241fcc56d6dd94294fbe7bf3fb09fdaa9ce564f8d97f90fc649ff5c893" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/131.0b5/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "5cfbb62d40c29559d15fa331e74879008c3a9f8255be940f270894106288b18efe3a078c140b18efd0bd2ebe43e021ae0e5030498a5c53143b37efe5fa0d47e5" },
                { "af", "58f9a8167364fb2a4dcb723c62dde111e5ffe82ea37ec3b6c71a97cfc4c5c1d232c98a5df7de9f20d6ad63e6aabf74019c365111403f54d61a1e47ba558a5a0f" },
                { "an", "685083aeaac6653e8d0fe1bbde282860da17cc6152e46d78ce98a5afccb6ca042319ee9a4048e5629671c98be4643f7d5bf8a23cfb30184b82a198918fe0ccd4" },
                { "ar", "5c106e482581e61169fa8eff9925e0680ac711d2d746bad019ea451905adaef94d1abddf45643a927cc6bef238ac21a92edc3f568c8fa4dd715c9230e605d581" },
                { "ast", "aef33e03524ae5c87eed91b7e93ffdcfa260c40e0e362766065379bbc003568c54af5ec4f684916f278e4cee317afe565d043ace1cc9f66105525d2b80abdc8b" },
                { "az", "cc5882df29161270afdef132506fcc6fea02571f579de6aa0fd1c13ce9786b0da0e4e835f9396fe71b4913e9b2b8f57d5bf9fdb517298514e7c23d24c5113084" },
                { "be", "cfb567e425a8fbf9d2eab7d8237a86245e9a694b0a3134a43fecdc55901e54b923b415ffd5fa3c56ac5d2922c52e4eb6bc6b840f1233658ed1f44d8a757ae75a" },
                { "bg", "b76256d013284825b8761372605abbe80aec74f30f60bdcda59aa6e690b41a5ebf1377bed535a401eec2f4eaf077b03b8b468f634ed1f3f35d267797fb2de09a" },
                { "bn", "d04abfd28c053b6fb7628d38b1daa6247856514df27bab4b0a8d6b48ac4e28013679d54fd558d8d9848457b778ad8feb16b963a9842c62c5478b04ce26057141" },
                { "br", "c1a370db39236a8748ac5b7032fa11d92ae22f91af0777c7519b1d55231e4c72895971f87930990b8b0a2a0ac1b608a06ff71e7a69e2d31aad9f981234c95072" },
                { "bs", "a881be1a3f9bc0c778f9792443f860a59c6435e8f3e951b2aba56868e5a90b4625f811633a33cdad06492f0a152ebd7e174929b50509218a5a379b17c0823ebf" },
                { "ca", "686c603cc4fc1c1525ad98641f7adb3230ce889ba69e281c6af1fd7cc063c66d83ff068053c82a4c92aec3a9aafc75c261102961a396b540a5e6977bce0a22d5" },
                { "cak", "fec727fc0cbf7641d5f151ccc0fabce0bf60db86150cfaf020e91cd621499500372f6360e2c8129f965040a1e2471c551a97744aeaef22792a322d63d1bce1cf" },
                { "cs", "1d58a296d12ce89920936dd5c33d05833a9d7e1343710baf0bf17b9a40cdb3bf099096a46c322f3e84dc7edb8cedb9e546cad37dab537cc51fb12cd5eff1a2ed" },
                { "cy", "64562248d4a5935c1ec5cc2d89f8a9abc86b853fce13b4dc0b820f6d7f4bb92d8ab3d3f4d2eed95dd2b5bc0bf3c8bc4daf6a2ec26c1e4549757cc27d0ece9813" },
                { "da", "6c3ccaf9e32db5ebb1b5b39fb36becad3f718594726ec43283a3f7d8fdd31830f30c5c3b5a64121bf157e23d36bddf49d922f48bd9d0ac7da05e6de9f09506e0" },
                { "de", "ae031849c6736c27d54bc54095b3931088c1f76b6fdd1eeb2e7bccb8fcb9314331088917ab55f0a8c4f6cd1b9d97cbccfb65f10128872f327806c591dfcfc4c9" },
                { "dsb", "9297687f31cde325c7c3e2d5bee745055d2f4c7b81b71f44567dbf8a786c8c1c9326ce27416e5a72f357017f88bb502cbf44cadf127a0dbe295272eb0044f705" },
                { "el", "66323b294a0bea9bbd47d7c3f39d35f51d3e6594737e6f538bbc51e8fd1bf06fd26eab7d175a8def815fda4e0ba4e2590f9249de538853c866e851053ab2bde8" },
                { "en-CA", "8249f1c358063f9115de7f786cf463ade4372b86c14e1dbb19a35b4b1cb12444cd9fdb392774b2982d5e9ef1c6c6f394f307e7c8714c76e60d08cdb74258239a" },
                { "en-GB", "e152661b25e2dd0d6182dda212f22ad21058556ef60ae040501f8354835485a6b1690e8cc92bc51ce7d2372972a3204254aa0271b464c3d5e82f3bc9d108e1d9" },
                { "en-US", "7f5428afadcb665c145b76b6af771f36197b111b25f99ef1cb3415479cf3872bf06b045bdeb872ce927aeda632b19a7c00a959d81d765ce40988b9e05fe26836" },
                { "eo", "21cd8774650f2affcf7afbefcbebe9c85ef3ce5ef0d83bd2db2159dc5573fb06854a771d81befebbcaa7dda3b399c935540cb6c27bd80a67dce2098db0ba6b67" },
                { "es-AR", "74d170f34f2fcd302741af72327d89d3dbb005fff5bc968401186745d79a87aa7a0c61a3cbc8d1a954b5dd8017c6491566cf3f3b4b8f233549d36d2b77837fb9" },
                { "es-CL", "687c16bc2bb7d5b7c7e33898b5b3d0d286e609a0d35a5aa1b04eb931dd44b06062ee744b09dd8f867966a290c19823da1b5fd6dadfeb36256aeed17a4aca2a66" },
                { "es-ES", "7ded13511e7afa324aae7bef2236dc3d483a39c17159916ae52146e514ab8d6d5133696c730c73ebcbc2481071347be044dd5623d4d5cf9ee82fe0209f0b4ecd" },
                { "es-MX", "2e0a237166fc0b2f836561e22d94c5bb84e5c9a7fae188fecec52231dd67284774ea7dae458d861e0dd42e615e2ddd3a6addc39a04fa1f896a95ba9b1b716445" },
                { "et", "82a5f4cb2aa42c4df5731028aa853375e266e61963a807cae4c5a19c1b8f065c57d0121e09ced14dcb59e3439d15b494a42a7d48922cddf299eae9e3e12d7d79" },
                { "eu", "929e6f2c836c57e7c844e8ccf7e9c900d496efe38c95080b14a21c791217e516dfb5af8dd52ff0bb9440c969113e6b56506e5ce3e73b356c7d12ff397f349a32" },
                { "fa", "201c4a232c37d4e773bbe440d75e785be469005ebdcc21d0d91288b6921b2165682554efc8e626ed1cc6aea47a1b418af80442665f07bda40a58c5b67a2893e0" },
                { "ff", "a569f5a818522c957e6d9d8321bd932828e669ab5d5cc4306cd36120791dae8da5d368838afec5bdf7a9622479a3918e35ab90062c3097b674e0e1c9ffc5c0d0" },
                { "fi", "280fe730fdfb0d886219ecaba0edcb1dd193eca461d9dd0123a35dc56a7aa88688fe6b06b3a61c59e9549764e44dc01606d5a392974d6b53923c421454243ab5" },
                { "fr", "cc4037bfd6edd4b5d05c060afd3448049ae67f6885a9103c30483cb934b6e0114281802e7941b8764bf76431fda4ae441d737e42e2365a5d4b65e669634b7fc2" },
                { "fur", "85b1ae68ff98e7db3894f1991eb4d10d5b1749cb605e9889bcdde0769790c36cd491e385d95b50b58fc4830f061712c9bcb6b7cde0c3d4b3235c9ee550a034d6" },
                { "fy-NL", "cf7d11374e7e0ae04920d6f642f73e9d7098bade86278d320dd200f365a163dc6d1a61b6a7283fe577a72a08aa7d343cfcd593784f797a6bfddd882637d589cc" },
                { "ga-IE", "d6ee0b22d2777006c0c35d64033f3c9eab5caab182ba5574b0438c4f34714bfa9835420223f632878c8b282e7e8c34e703bfd5626a69b135bafd5efb1be6404d" },
                { "gd", "df1482ff5250258d32adc4f68bee2d2ca0ef7312a545736570340f9e425526201b93b1e49d49c11c5f0a8b93cffbecf75117c6a6ecb1754c20383b2973f50682" },
                { "gl", "7958cd1fe28035e1be074c6a223c833d10345de5505a228ad2b1bb199db0350f2a09cd13d41ad057a66fb37fe7b27e7b9b4a8024820bf8a21ed612e2e4058c32" },
                { "gn", "cc6ac4fb8a3c59bc96bc4e92a287880ce3d61224d7a9cbf786286da2023174426663085aaac7f450c9ee348e07d69538c62b136465e573b52fa23ada7e9cde23" },
                { "gu-IN", "7bebc7006f21490b4068776877e27828234cfcf3ccfd5e22e9c2e807c62e4e707bb9a680c54c6e5611d54050968ecf4c38e6deb635ebf64f0683ebf574060a3f" },
                { "he", "0c93b5c880c8a695848236ba3e4cad5982d0b93597dedc42ab0debf5bd72a58ecb54397fe025b9c54c37503f3484594f8eea8902c3f6620464f8bd4b0f82dd4e" },
                { "hi-IN", "fa433dc29f659adb3108fe3037917016c40b6eed719a6a4850b3de9721c6e88548be291b845fc8b8310f1b9490ee73897dc80866919dad6e74486ee23c021218" },
                { "hr", "98dd7b827d5615cb24a2844960d98bb6f836d37cd8d4f8ce79dd89fbb67c695d19a3f7971e2e2d166821c8c47fa6c5feca2acbeb1a992d77d907c1f3b3816270" },
                { "hsb", "a129ce1892e21c17cb6ea175d9e8e672c5559be8103358734e82b9d54dac4854211e04051e2aa916d68dc33b332c91f5368231ba423d384d57ce839f92f3909e" },
                { "hu", "1c50c943c111bf74ef1d63b51fcde192118edfa991df390a96f770c11a7729b607f46b8025080efb29ae4ce6a1b783459550270fdcd06d877609a2572a786a10" },
                { "hy-AM", "4b16aff6b9a1000bebc664c890acf6f38bf09d9fcaa64fd85ba5e358e5de08464f6a48bfc40a16348b499559761d34ceb8fe5b2935afc901c6d966d8379360b4" },
                { "ia", "d9109d82e13d3f1a13005b1ea3d5c68dcfb342ef70a7ecacb506c1358fca4fb8de2a1cc8a9b1d028a833d5e220d2bf330aef5266a057f2e79ab82fe2e54bab93" },
                { "id", "b1cf2da9c3f4289d9c660bd6400bc6cdd7cefd4d883c2b5e72389cd70f6e0e91410d1cddde3d3ac2c2f997296e87b30d24bcd41f65db4192b2cdd0268bbf5548" },
                { "is", "bd7ffcd1d67c870370c2b5252eef452a55ace6af33a035c5f9ca6285034f79b29574768c33c400c6366c2e69056b552677b83ffb6ce9900e227dcbcb4f5a99d8" },
                { "it", "db71736210585a4dbff4da1c45daf630b4c27300924616eb0961a2dd47870cc4523ffbd37b9709331597a19b7a3b7899f6da68916e55c755d35c64ac4038e37b" },
                { "ja", "51ca9cb583bf0f7406a05df945c29b660619cdfd63cec77d6087ede8891d94f02e1bd40c6a88012a2b0641ca0016e73d78cab4dd412cf647d105550d4bc01fc5" },
                { "ka", "8e9c648cb4246fdf334d0dc1da42272e851d819973204e4d3c676758e061e1cc86fa1bc9f1ce594a282186e3aee4d8baedebc900f37d7de4d2d28556c5f2d7de" },
                { "kab", "f0eaf3fa4d0ec42f46d4904767186887ad4ae64c8c2358cea9a12285e5b6ec2d0b2911568a07f8b0f0e29e1d246c27c77915b9fdfbb12ee178f36315bc9252da" },
                { "kk", "6a6f7adf2365e615036a4aed793b488bd5130fac2e4d3402751fac88fbbee3b83dc532ebd6874e2525c737e5d3e479d978a63a2ffe4f0dd548d35280f2b2078c" },
                { "km", "5e95ed76bee564a42853d313596974f6c6687d96eb0779bb1ca54433b955e3a52ef9bccdb3cfef4b89b827c77b301e0ab270e7e3550018855e0a3309a92d4937" },
                { "kn", "8b37a4c4d6a19376fadf72ac5fe62163966332faf8f1e34533ffe33d9b8c218ab2588e2b6345cabe0749f424c649270103e0371e9d8d722ee873d1fad6a2eeb2" },
                { "ko", "72992032c04908afdca34193daaafe337b0650572ab64f5809e94353a9b6ca40c599edb329cdcaaa4a8d47c6fdb3270323073bf0df94d69da0bcfa6b318429e0" },
                { "lij", "28392008628d9e67f1ae235ba92ecac05a5259e21f9735345194aadf316177a112c3e57930db54b07174f21886c50849477b5d2b677faab5b55f3b288c6335cd" },
                { "lt", "d926e466524b7c51bd8283d1a87f620490f98a81ded3fad81b4e915f37e1962711de04acf1cfc25958f30a8daab42f6fc274de44abba77e69fa02563a5f1fddf" },
                { "lv", "0ed33d198c74bd52a1e2222b5552ac9572b681cff68c8298bd2d40854d65479b4d42ea419136a522b2388a8690665829ac20bb26d95801eb4978fd898f18f9d2" },
                { "mk", "4cb0131324fddfe530a7eef6d3cc5da7cf6c8f7ae3ce9c421be2a18047a4d0db0d92857a1aef8be32c2c53e22271400e62e132483427524c9ca4534281745020" },
                { "mr", "a4699e5e27fcc8983f83c5bea7276d723c8952f9ec65dc4e1c36044c22096bcdc90fb5e474c5bc0cb82ecb08359985de48e3b0ceb1529c9f99723fd3a43d28b9" },
                { "ms", "7e6f92b2ccee5de4cf8edbd07963b284cd825dbc14d06cc3be918fd6785aedd22cd610b62d380228aba5547d48696f3e615b29f4ee3626c86dcaceb6eb00cae3" },
                { "my", "b22366af9294e4fdec0ac9fb47a7f2bffac2268ae2da1e308ba9ea5c7d060941438e7c224f1309c403e0bf7727d30ca4b1b9d98dc0aa29c3b5febc9f5ecb3240" },
                { "nb-NO", "a39b40086d0f0226b2db7e57675381f7bded6ac9a44298237ee055b0ef6687573245f1a951cab0b6f473f76c8df654145769d47e26d6c50b65af1586fac3da06" },
                { "ne-NP", "f7b4cea38582f085c066ff9e6d83a0b3f6276026cb1b12ec20cbc8b3bd8f8d089199d1d09e01e1e5eb2e3b32a6ff7b67d008769476a46692a5e92b4024c6952a" },
                { "nl", "6138995efc1a1a37b0b640905f666df980761f7a67d8890ccd6035f57ed1d45bf83b18e382b421e7c6b9d11e1fe45e3373fb2e2d488b194da13e2ce77e120f79" },
                { "nn-NO", "b037dc3498c092add2516ae7f0c73fd66b91a56a9252fc77c610d50825123a0829ab47f20e40cf0f3dc472a57e509f73391fe2fa339af6a37734cc5128bdf864" },
                { "oc", "0f6092c8c70fe36a3c48637436be9e8087548d8b82a30fa12a378860235034c651518645965b32ae1a676e7d5b4451a32ec195bb43060babd867b7eb8082b881" },
                { "pa-IN", "dab2146f19ec97125e974e5ccff3db86f3baf48872a2ffd98e52d160abc99318fc700700b21d8f6e931dc2b3ebb492d27d3b5daa50ea42f58e9bb0be812f99a2" },
                { "pl", "9848ac8af6a94a0f5da031a84cb47e2f7e5f47139fc75dd2edc33ffb81df87cf25f91e6b44cf109cedea18a3f4ce85be6e961eaf7f4f4bfe5e13ca17990cccf8" },
                { "pt-BR", "f20a57438e15554352ee800088d7861348fbcb411cf67b406f76e267914cca75140214e3bcdfddfda6203f00d03e0db2a391d2f45e50ecc558364e7e7d5a4a1d" },
                { "pt-PT", "a7babcf7d7458fe6d2b93f308a6a676e9d6a9e131a9daef6403d4bcd178f5417cdc0b05535fd319f5c2055fe3c0a01efcbac9336e5a2711860051e6dfee9a215" },
                { "rm", "ba77585bcb58fd8056a23a1e9930c9f5edc9262694d007426942ba57ada60b23494328a6c409c537c501ead56dc7e238f41fb75e4e7861de2ff8373301c5bada" },
                { "ro", "f9db2ea980aad16aaf900e4d3e31c81ea736d6cfb3a3abf28fc8b33967256ceab41fdef794bc5abc7e7870a7f3baebad571f97bb4bd88185cdbbe225103abadb" },
                { "ru", "6bc181e89652d4b24f7cc633d4c6e3a3f76f316e69b99c2a3effbca95c3d425d5db4b510e1a4e9d3b2b9ce0806856a0d8d3016d1bb278ebc40cf7dbb1f955534" },
                { "sat", "8a6e21a3331b07ff10fea475744bdca736c1ac39e81c1f2cadbd63dc89d5645a6af08988b9ea2b5516feaa87a5eca023834e6594c179813965f22b26d10c6142" },
                { "sc", "561cfdbfea8892c80ebbee78db2a4f0310133f92b71b8a32ed07cf08a7a4f905fb3522088ba57e9fae8e10db4038d6bc1d295185e2d93be077ffcb53c3341f40" },
                { "sco", "12664b72b7a5a4c928f3c35fb58e6fa7c8d72faf51d28a57f71544cd68e012c81594d6218c8e8169781a74e63c54daf49d51ca7ac87ae2786fbff25956da4c8b" },
                { "si", "79141476bc1ae2730c8c1d9d3f73939798b60f6753d971496720cb9dcb09f00d58e163fa6c23fcc66af23a89a0d2f76a3532da022b9456de57ef682bf49bc92a" },
                { "sk", "bd8212bbdb85f48adec3894faa80d911f4037485075498d0c7e0f9bd8fbfab2701b4cedf14d3cfef5d066528234a21024eed0cf79579b7b2d5a7774a33090432" },
                { "skr", "0ab51b6359c2c116b787f7c0b8ccfc1e6e03459443fe5892bb22d241fb3a1011d2585e9238511aef7498dbf5d364f6fcbaf9a739a75a20c8b350ee0d8dd5db9e" },
                { "sl", "42cae3c2ec672169f5371451b05133c4ba1f438742fbf9ab5708a3a92f87a12b5e3d3b3a481473f4a9ae962412f8b238209692c5a9096d78e5ed6e73ad4724cb" },
                { "son", "fc912a313673fc2b3aa0297b2e471e2f672353265216c06a7175ac214848e3af446323f80d1f86e2436ad2e3a31ba6d21049a5558645c2685c4c7816a07d39b8" },
                { "sq", "b08c3377c87cb0f48a8a8079f1a3cee4e33efe3e65c5deba4f48e1626c596a7d3c9c0e7391e1ce946baf1f6e0c58add079b124197e877a3babbbcc550b974b44" },
                { "sr", "f8a57b11cf298ea1f19eacbf94c252c4c61a4fdead7998085242c5fa6ff4c7f36a767fa3e1ec37a96806366d76e4b824741cd874c6f4f3f13beb0ab784e4e9d9" },
                { "sv-SE", "f68b20784afbf960cddd0891a434cc0c8c8bfb4311fb563ac71e6b32a67111305d5721611986a7666e4181fedee16f35456efab6c06761bc72b94cf2c4b4e244" },
                { "szl", "b0fa153e99d11a329eceab3421957b9dc137f365f2ae4a9a80b4d75224e529930b5deb5972f6c498e4f829fa44fc57edd6fa57a29212997c04b0d649fa178801" },
                { "ta", "e382280aeedd2c75a4ad751607752751d444a81f4e996aec478823de018315251cf477d2509ac68df6295346f776d70b12568412bc04c4fc5f29819c224b6ea3" },
                { "te", "740dee6022296c4bee968b7414e06eb576dc967e3ef71515fd0dc50044f1361e551de266d9c6fbc13c89ff314eb0e6c6fca3c547aeb109b833d14273b681ae58" },
                { "tg", "4a17e6f8f185b77a51190e0db6b8a18e8b9aaf0cb6fb8314fe927b3e4b7e22c9d9632c222a51922f4f8ee0487555d7dc1d640b0db513afa570bf3f3cec4e75fa" },
                { "th", "ea224e4429ca98aa43c0a1a7405f8b96af324faeb1e80ed98154a81a5efaf8afe27beb675a745427b0998a27a42b25f0a7c149ddc9b10f2a1fbb510e6a6901a9" },
                { "tl", "70b4b7176ceb67b85633a4d22e1e9c7f4c4fa05b429849373f648d735de71440ab6e6ca4fbf5160c323dedeb3d30d7f1cdbccb34ad485388a5ac9d9e55a37d7d" },
                { "tr", "5972a247143199459663aeb22cab91f8624ac6472de112ee4c6872c823b55990b1697b30d50fdb97b7c213d95cde21e6fae0057608d92db05f0c2be6880f86b3" },
                { "trs", "b0aca0cadc32f42cc36b79a2e2dccf59ab34fb72d5d032c1325227b9a2ceb65d2607bee098e77ded306f39a5784af29c74e38e34b15161fb358dd1937b879db1" },
                { "uk", "182b3b37213a4cb574c696b2addfe5b2d45dbfe8787c821b6428876fcb4a1a1ac9f951559095197e79a1a6b422dd84e99a422f36977d9692e0de279c6d3b9184" },
                { "ur", "dbdc1cfd38aa15b426e01f993cd20772db5e8b3678eee93a52adcaee35b70409dda82621355e85522103382f4f30cb9a057e3e788aacf39f2a2ecfab559fd5d4" },
                { "uz", "28310e4992b22148850b39317707380b68741dca139155fe31d6baf4acc619dc833b11f4a4afb3ae27b975f42ac515b667d5a527a0e5bc7a646153867573a142" },
                { "vi", "97eaea9b349282fc023b4528376f82eeafa6d36d72ee2276a3331aa8d6e7a7ffdabd6f98afd924d5413a2ac4f73c0f58b60b1f5fdd3c941d29d12afe72528aef" },
                { "xh", "d134acf84fb3e3b8103e6da26fa74695493d096b3b365b2bbd76927c02847b2cc6628d47388d0462d6298366cc8c6984280e863e2bef5a46abfada63372ce642" },
                { "zh-CN", "f143b703aea5c74fce3ad86347093ae1c056a63098005a56c816dab1752d9ef3873c71c6387629574dad189f9fc6a72ef7ad2a9da4ff077196df84a08f4ea861" },
                { "zh-TW", "43c41a563e142df0819a1a4ff1c6906e92d298c4b8956570f3246573288b1440ffb09817b8c51f269d4340a11c5f57c1ae2c87b2415ab756af4f0bc28318c75e" }
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
                // 32-bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win32/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
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
        public static string determineNewestVersion()
        {
            string url = "https://ftp.mozilla.org/pub/devedition/releases/";

            string htmlContent;
            var client = HttpClientProvider.Provide();
            try
            {
                var task = client.GetStringAsync(url);
                task.Wait();
                htmlContent = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox Developer Edition version: " + ex.Message);
                return null;
            }

            // HTML source contains something like "<a href="/pub/devedition/releases/54.0b11/">54.0b11/</a>"
            // for every version. We just collect them all and look for the newest version.
            var versions = new List<QuartetAurora>();
            var regEx = new Regex("<a href=\"/pub/devedition/releases/([0-9]+\\.[0-9]+[a-z][0-9]+)/\">([0-9]+\\.[0-9]+[a-z][0-9]+)/</a>");
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
        /// <returns>Returns a string array containing the checksums for 32-bit and 64-bit (in that order), if successful.
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
            string sha512SumsContent;
            if (!string.IsNullOrWhiteSpace(checksumsText) && (newerVersion == currentVersion))
            {
                // Use text from earlier request.
                sha512SumsContent = checksumsText;
            }
            else
            {
                // Get file content from Mozilla server.
                string url = "https://ftp.mozilla.org/pub/devedition/releases/" + newerVersion + "/SHA512SUMS";
                var client = HttpClientProvider.Provide();
                try
                {
                    var task = client.GetStringAsync(url);
                    task.Wait();
                    sha512SumsContent = task.Result;
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
                var reChecksum = new Regex("[0-9a-f]{128}  win" + bits + "/" + languageCode.Replace("-", "\\-")
                    + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
                Match matchChecksum = reChecksum.Match(sha512SumsContent);
                if (!matchChecksum.Success)
                    return null;
                // checksum is the first 128 characters of the match
                sums.Add(matchChecksum.Value[..128]);
            } // foreach
            // return list as array
            return sums.ToArray();
        }


        /// <summary>
        /// Takes the plain text from the checksum file (if already present) and extracts checksums from that file into a dictionary.
        /// </summary>
        private static void fillChecksumDictionaries()
        {
            if (!string.IsNullOrWhiteSpace(checksumsText))
            {
                if ((null == cs32) || (cs32.Count == 0))
                {
                    // look for lines with language code and version for 32-bit
                    var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs32 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum32Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value[136..].Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs32.Add(language, matches[i].Value[..128]);
                    }
                }

                if ((null == cs64) || (cs64.Count == 0))
                {
                    // look for line with the correct language code and version for 64-bit
                    var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs64 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum64Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value[136..].Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs64.Add(language, matches[i].Value[..128]);
                    }
                }
            }
        }

        /// <summary>
        /// Determines whether the method searchForNewer() is implemented.
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
        /// checksum for the 32-bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64-bit installer
        /// </summary>
        private readonly string checksum64Bit;


        /// <summary>
        /// static variable that contains the text from the checksums file
        /// </summary>
        private static string checksumsText = null;

        /// <summary>
        /// dictionary of known checksums for 32-bit versions (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs32 = null;

        /// <summary>
        /// dictionary of known checksums for 64-bit version (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs64 = null;
    } // class
} // namespace

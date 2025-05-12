﻿/*
    This file is part of the updater command line interface.
    Copyright (C) 2017 - 2025  Dirk Stolle

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
        private const string currentVersion = "139.0b7";


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox Developer Edition software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
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
            // https://ftp.mozilla.org/pub/devedition/releases/139.0b7/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "2679967b11d303c820e6dd6e1c0c8009d640fd466528eeea415f7f79041af637d2d919d677835cc718ae6f5fc9079a1d22ce7fc7d05873d72a23b3b63618f740" },
                { "af", "5494e94e26ee98ef581332531d79dbc8d99626e0ed9adaafcab9ad04e4f76057ae454b6ec4ecf746c8b71c7246555b072c77f17437cceb95e9e0acdf1659a3eb" },
                { "an", "ca3fc0765f7a461564a211ab01b523b7c79de87c61ab78f286993af644d292aa9d7594cf0ad1e8d80c3e1d71f617d6ce7fd6ddbe9eae84d36032e22b46732d48" },
                { "ar", "1905e50a04f217af5f946c80c61eb6dfc3de9bde6090c8e0b0c2874866cf741e6395ea18dccf06eacedfb48511e3825d5fb2058a310cf1053d948cbf481714db" },
                { "ast", "003d5209ec6108cc4f8b3b18a53095cdac20b392d8c0b7166f5580f1b5b689e4d1be5917a305002b3fae80ae340d4a3263e5546d1e414d652e37aa85d56ff493" },
                { "az", "c6d24649d326609d8dfc8f407de5dc85f48461ada3bf879aa61c7af2c64148558ba131c824f21c7edb104cb9773f1129322bf3f693a10ec88030a2bcc151f3de" },
                { "be", "5fb6f586a82c0d0c1ed560e8b8249da0566fae2b7aa89a51f94d3f69f23568c544b275ded89d138b32d7b7ccf5be69e44d8ef544951c13a3ca25e8481e0b1979" },
                { "bg", "b1e8f966116aacdea5d7dfee9fc4e1a93b045f19ffd8234a49182d7f2bd336cb884e683e9c30ecf8b7851ab6ee56ea8eff7e573a456ace18d96fc92cb0a7d3b6" },
                { "bn", "7352b04bacdc59a44575b757fe3f229302c48ca731cdfc7840e9a593d7a4d9f961947f0450f012179863b28003275e8b4457437d047079aa1eeec9c5e8e514d6" },
                { "br", "2d27606efd7a67c7d2e56267915c29335c7d42583b88bab45f879a934d67fa0b8f1cd77686d2c6f8297997208ceeae3310f019f67d5b6317cac21958592c9d18" },
                { "bs", "c7ffbbdc7b37dc9bb8c8fb8ce5f21736ab418ca1fa7f0c43f7cd9456676a0e9d63c3b0d068d2592ded55586ec6d1458e9884749acc2e0dc2df0e1863159efff9" },
                { "ca", "7f63ae495d215957d24295a408870cab884da7471cae56c3d3f5440e3286391486a6e40dddaab3627afbcf44eb58f905ef67b4753b77f09b52ef34d125bc912b" },
                { "cak", "99f13de3bd030309a9d557704f8a677cdd22c937d21cdd6ee805eb64bdf84452f1085b13257599346c112742608827bdb1a8a32f38d5bc30d6eda0e3fc59667b" },
                { "cs", "4b715e159b0f43274f8274f99f5531ea9d0600b2c031cc3de3b67a9381b651be2f8e272f17e1a513a2f2a189fc44402a9b46c0abef884ff9d32fbdba5d4c2abe" },
                { "cy", "2ca0c27e6b6d1ff210289446144bc1cdafdf0a66b4f054440a28e20823c952221e36f950f31f8cf654fc9a6ce3d436105d0d9d1a0578daa4c483ac2f3108eca9" },
                { "da", "7a6a3199ee093a66a9493821ea6d5980601edaed81c18d1e74fa350672db12332e2d8bba8a5ffc066a15ccc87bc1ab1c88364d0271b3e992941ac129cdc147f7" },
                { "de", "9355fbb55370b6e30d355ad46937f866f82ac8acb1927d1dc8711433bf021441a77a9f0721da8da3bd3fa778bcb1d3b980a0430a3a8c00613a857c65b26a4f7c" },
                { "dsb", "06144f807a90787658f72df90803e7ef8308c6baa24cfdbf2a60b95ef9d907963c781736f950b429b8ba16895374927cdc73d24ca823f85a49ae56086d7051a2" },
                { "el", "a9ea6b09078cca5ec30a76ee3e7c04d7023be958cd6a5e7e175dab280894272cfb1a1d92cd1a41bf27b004d042659d059649e8504c24bb6d7e350f2342fa51af" },
                { "en-CA", "62a8711cc5b2c6cb9701c93972ef3b94406f04060f50ca3d4d27a1e9722f426d7a8f95e900fda9115a531098c23e65d73240be1ca2c7268d107d8b44b3e706fc" },
                { "en-GB", "f1560fed81546f27813a9ff433673a1d870e1fa9230d7d82d760ad39a5e9471e8941cbd6e1e4798e9311ec68eca2ef09d915c1a399697d82b39526dd000e2942" },
                { "en-US", "cd785d671e76fc6842e609607fe4c03aacf49016e297ea8f3ee4134ae1520f25765c9dd75007ffd43d684fd60c1e07ab4e0f59459efd494fe16495fbc78e0af3" },
                { "eo", "1013d805a4a75c15a60f7069e0005e1bbc9ee35433c4336385d1b3ad722296616e14e95d88aa55cc5257ea2e249854fa8fdaee8371ef35f5282db3735866027a" },
                { "es-AR", "d36fd496601e35d3ddbbc296970bb219d7cbdd237eeca97117a3749d70dda1d25179b7756690c1b0e4727d712dfc4330930d8c777508bf7b5594a47b85e098ce" },
                { "es-CL", "424145595165e96d908e71662031371b890a26f2c8723edeb0991addf975608f2459022330ebb7a8c6b60f4973128045bf30b68211fd5163f4358d6d5075094c" },
                { "es-ES", "1e1f3b317a67d6cdf61676cfb34a0dc0c0bf0fb6366c615414d112a0a162c1ec3751a09dfe22862e1fda40ab73cfd12f65225a164ad3b743bef5af91fe1816ef" },
                { "es-MX", "046c6edd5d7c64880b446aecad7be9a6fdc2e3694458d54b65399338502e79a42fc2035af03e1fee5e3bdf11b97ace72d8bec9004209c1643fc127d743f53cea" },
                { "et", "b8de09ad226240ad1f3e9ac61aacc6bf73ffaef933ee8780c8e0de6dbd09e59df94e31a95868cb10d802a8f80b8eeb42c66541e301d2654574ae39e3ad48c3c8" },
                { "eu", "f21a8bf37f6142accf8991f0b65c79f50ed64419a067e5a5752191ca3ef0b0249d2c0fc3d35ec13c456366c2363d147c307e40db062ad081130a35af1bc45c32" },
                { "fa", "dad6afc0cb2c441202b37376f74eb2cd1f16fc8cc94d2b28704431a914aa30eb5f39700347778bd2b4ea247a78a9340ff0f1f8ec33b67813eb08db1008aefb38" },
                { "ff", "52434c0068bdbecc86a91006676a867387f3bdf39c7cf61ee67bd8347bc30c779a0f44cd87dd8643d50e9909e4a4159d98eaf55e8f069b669f7c891c050e7f1b" },
                { "fi", "59d9877c7b8682bab94a1c66af0843191b6257e542e14c23592d06b4991d06975a9dcab229c5b9edfe2f04c4a43695082fd49b6fabac977f3f8c76db5dd27cc1" },
                { "fr", "67980f8b690e29daa3778e8eee74c7fe1a9f67b374060322fc5182036bc59de288aeacbbe59c1ce96bd2f9b3008a4e29638932de9a7823eeab51e068cc0ee9e7" },
                { "fur", "2048e35ba58d00690d30e5a93385d676c302d1a32bce6c5595a4a27eacda55357f69e92d951af804e4e721802093b2689fe76e88c96833752c73480ddc8d9efe" },
                { "fy-NL", "db57d52962df7746ac46003681aa350df41899875c7ced7a574d8941537097923fc14ad254600b82ace8224bbeaee6f3e4877dfc13a9446e3f081bd002f4af58" },
                { "ga-IE", "df8db88ad64dd56dfdf8e20a937934878951020d499d4328f17fb3c581002c84dc8175032ef70b668cf94fb7f5a94518ef6c9c04057eb3c6946a9abdc7b91e4f" },
                { "gd", "275342ee0e817c90d7ec8f5a3f638ce5a6050e9ed991f1da306ad1c7d6fca266f334fd9b0821ac75b92dcaeb56aeb0796df65d85ef832cb4d08e16f877501ca4" },
                { "gl", "ab9fa076bb2048070da09804a666bf70a411ef731fe519e17ad874720898ea02d6ed8aeee48585afc8de6298b818a308debec0ace6abe30b7cee9fa1e156d76a" },
                { "gn", "80ffbd638d6c6caa9da30b2c3190db8859a30ebaec0df7c641238f06072c90c3a4e2a68d8b5121261850268f383aeab8e5f2d25f72418f44f1b31fdf3ac69ecb" },
                { "gu-IN", "87a6a1cfd4de039daa9d8a250a726cfe545f914f6b66b1e87d71df40cdbdf2a6fb10df2b3622a5fa19401188ca02060563aa62f2198aca32f001d22b89d9bc72" },
                { "he", "f3015e209ab9d4651cb970449fb7784ec9d4d3ec90fe052a3cf62f588ddc304d51abdcaa8d17ea1d6c4c523439777efdf004b8b1765910ab96143dfb6d15b0bf" },
                { "hi-IN", "e16850ae469a61921512a644f38f42f263f891166f908d6250877d6cbee22c9f5e032d40fe6f9f9649210ba3e69cac322b80608ee9a595efd1b546b1503641d2" },
                { "hr", "307bd5b59066b4bfe747b53d3d3e76a54e4e736ab2fc6dd5dc7c01eb9c1feb1d922aa3117be45160e1f4292eda2af03eaed9823b7a6ba87ac82a823f52b9260d" },
                { "hsb", "a22b6bd57d2974a3371ecec27a13919027915633cfa26a09358161eb9de09e9ba3d633621c86de551ba7eec9034372a6bab3594b52f7b00c51cf63e2160afa32" },
                { "hu", "b854149d7890a470e94a5c742f7e83d67a664ab55a1cc798033ed6bc5b2d2597325b60d8e16e846d1504804b554c9c2897751b273ca2b7e68e8ff55fbc4a5bd3" },
                { "hy-AM", "dc0a9427df2da0e31bebcfc026e837c49ef3df5948674d9663e83282a9547253939919283a42df91811f306f252066af0571f61b1c1a34c639a9322126bdb6ca" },
                { "ia", "45747c5d3f4cb83ef0f9d16857e5ba60af7407bfc4f16e750ea7c1d3f28b401cc03757655c5e257ebb5d168f0e71fcbd9f78cbdcd6c27316ce980ce401320381" },
                { "id", "a8a091d06f00d8eee6d616a16bf563c30098e2c749f18ad309e2dc8ec7a68ba4d03cf99e16249fa72f5443142812a430ce9e99e1912a8e011f98b7aa72898717" },
                { "is", "9738dc824395cd000580eb54c4186eeb4ec6c60c706e20c99d4ea0837909d8af89858f2244e27ff94c9cda007086268a851215f31c3d676b5dbaf117ef69f487" },
                { "it", "adbcd022acd24bf7a717fb70dc12b6885a615cfd926f8f15e558b8fcd5eff4336a47735ba465fe9c33d9f31bde6f66e52106f7cc4119f05483a65d1653612093" },
                { "ja", "41eb173ac3b79730252b0806dfe6311c3aeaa45639e10ccee2f93d4727d6194c537d4b8cd4c531e27d1ce2c3e512a45b0ecda143f54df377ecd081822aebcbaf" },
                { "ka", "14f2d95a44a661e98ba3ac75ba0071e3d6e712d102ae86e123e06923174cb8a98d675e050f821aa78a89626c44edbe751286d9bbfd34560798a150c684164e0d" },
                { "kab", "c1ecdeb2f03904d42cc829729c6cf38db4cacb071cb2a20ceb3951981461b7bb009265be8f76ee531298392dba346bda30891488d0e2009c4dd611c4e373818a" },
                { "kk", "5c1cc9f54d092175baff946d04ef6b12fc3fe702c5f3f2b2140d67e93b701736f190ff1f35aa9632cf0da00c5b2510cd02be2eb5f45bf6a16e82ccbd85097d5b" },
                { "km", "01645e694616379cc20620a87f6691de74cd998a98b986a1ed91af105f30038a36ad3a1da751fdb8ccbfa67e2273fcc2cf726c767a3e6cf27af8be66070963ef" },
                { "kn", "5442a678207492ac4c9b55df72cd777f0baeb942a7cefe53bce4fb257ee6dc9a9fc9e6fcd3d039f686422e0a48f65f5996d370628dd54377bab874e793fdb84f" },
                { "ko", "eac56c136566ad2950db89358531be71de3e9671e1a0bf1ee80f348b483050fe8eac32797d679080e672d2e1840a05019dbcce41728d5bfcd7a62983c94c4ded" },
                { "lij", "cb06a85c73f0c5e143783bb00632c3a560bdae7dcd220b2355374ed981c8da53b76fd2647173365d58189b2983425a09a2aca68fbd78a69353e9e1538cdb27bc" },
                { "lt", "88bd0e1fd06833ac4fddbea64899dbd51601fc913f8f0b92fa56729c57d7e2e717d623a866ac475a1f6f6f36ad7aa5df53a1eee7aa24d9d0a8205a55e762832f" },
                { "lv", "5fcd53c3b264edc87ee2f634df226ac1ed8e00fb9deb48069602fd7ce460ab552e688b6da71be18999d114fc3ba2495b392cf9a44880d4fedf1927024f1ce4c9" },
                { "mk", "8e609dda6b1a8f6dc3e2c14fb7d9fb58b1c45a9c83238b727d28d1ff3ce038db686915a5e59caf3f99a99475e76d524bec2440fc25808b7925d0151dddd6e499" },
                { "mr", "93dba7896131684ab4dfec88f62f3d4231cc0141139ae1034e843aaab2c73e2a245f081d2ab80fc6a272d881df0175e33cf24ee8cba2b013d6dec06a1a26db6b" },
                { "ms", "c4d0aa733c6dd3615220796ed2224fcd04f870a79eeeeb10c47c38eef1336b81d2cbd5d6d82a30bfb75f7e620d5d657e2146ce21599b308aba09ec6f3d70b8a0" },
                { "my", "9b99311fc510291963120084fb05cd66a0c244c8799c7e0a45cdeeeec12f3d3a7424d411b0e9644d82a840fa6d59637d709a3b3e58624c8d558baae07359a419" },
                { "nb-NO", "7ee831704494a392f39f8a8473e2a83b613de8174475f1367d6ef21fe16ded99306573baab2d14745d29a6b0b72fc83b19cf15603e223a0c33aa2043192d28fe" },
                { "ne-NP", "50f9e4ad10126f555612d051ee5597bfd689a88ea5908759af1d5f346b4209a03fc2089c69322639f695421a3ce3d02f32a63d1c32f480f45659247cf808de9d" },
                { "nl", "ef64d9b1f2c1c126941cc94a9862ae07a57d233100029b8229bc044d97adde4a9c3bf28a4b601901ca3cc1f7adddb2f324027ad01888dd50663361c8efbb9ffb" },
                { "nn-NO", "607e8e0264aeafe188b1ee6dc3855b6984c4e30c132f6d2d094599b47e052067700cf71ec5f0fe1f33ff6267f10a0056fc53eb7e3527a88a224c7b5b1c5dd2c6" },
                { "oc", "118bae1b8837feb807890ea12faf89574202c67c8fbd654cebe72f9afe6fd40a0c19405c9e61f960e212262fc854113bfa592c86469523407779460eaaf32d5b" },
                { "pa-IN", "dd1b390b73dc0bfbb288901b708418406128eb860786e546246a3c4b2d22845066b0294e3fcc8a41b24acde0f206b052194c1cb311e5d0daced07ab6aff972db" },
                { "pl", "1ce87a31b0b0ff245134d4ec3abde439b6c26618e380adf09b27ebf34ba42e7ffccd09b73c22a9dae0a3a64292734fe53aaa51c1505f41a30f79f3fa5105d10e" },
                { "pt-BR", "c253a886a87b711b4789efb0725a3e06c591e0bf97fee27d3186862f093bd6cefcd52306727816ed83b42abb73b0428eae490898feade6e4e0c0eef2a3a3132e" },
                { "pt-PT", "4bf30c8925d9bcf275fdb1fbae21b77d9ab9b2828582edcbbbd0373b323cf25672e484417a3b601063721498b445a2a40ed3f8cae719d8434279c87fffe9bd59" },
                { "rm", "501671fe6e0ceb3dfa94b01836c8f8eb08ca0349b0473155f39efb5bd61b9a30e462a7c751f2aacac601bb69698dc81680a0b6d6f13631c23dd221a53024f37c" },
                { "ro", "9e5fe48b34d3a12a0aaca37f0d906dd3ec3c064650d70932d789f56910346a9e7428c06398368e8342aa5f4782c8640f999ebf5072c84ea1e80790b671277fa1" },
                { "ru", "34e4f1fb93477460ff50b3ab5b3c66b55952b9bba0181a2a2945526c2861383d397bc651b9f928ad76203833e1f8a1c3dc793b31682e8ae8684c03f16077cfa9" },
                { "sat", "844f36b169befed58f56495504e73b7a542604b403e9d7e4c07cdc93dc439b76fe2ccdc252afd4332af4ad75a7076145e54c665d22561a035b70bd567224a500" },
                { "sc", "6c0224be384b311ad0f4c0e9ead2650b38893a6c6856bafcb84b2cb43861f8ff5fda1acf669c8ee2eb1392a8744a3e113d1533635498ba7e3549e49b6eec6814" },
                { "sco", "3f2ce1788e72d026490f3f78e4f3181ac30bf12500b729f39cc0434b13c492b31a3d15e4be0ac2993c0a24ded3bf6f0850bccea9cadc367f55f5a78bd13d6155" },
                { "si", "0ff4bfdfbd4907dae53bf919614af6d484244335140fffae145bc19d392fb5faf51de84af23075429e7d9429e8afe2b836cfdb3e28b094ea58e31546f94f7393" },
                { "sk", "2780f0d1c9115760d929f1ef8d4781570dd94c1be11ae35f4e6aaa3572f997dafd2f0acd4e516abd8fa1f65dc33d816d0b5838fa2f2d3c83511b54fb15a73fbb" },
                { "skr", "0bb1dca551ae763c52217fd6c20677e9b96194e74b841a225345db0986b2ae5797725ce513e1e2927245fcf36af3a4997d0cbfe189cd13f4bfb3758c241c303a" },
                { "sl", "8eb9db5a9a627afe7c1e377eabb2210d36e5455865d305ab66fadfc2894fb8a99a0584504aa1d79d264e7d5f766ea4ec36a76327d1bd385bb713221be0c1516e" },
                { "son", "be8166534c9cc3b7bd1fe7d2a1a71c64ba83bb410ed6335349e32a0c538a1728b0e5c03fdad48dd195c9f199617d4cce2e71c9fda56f8084afc20ba2eaadd6e0" },
                { "sq", "52b23f5eeb3993d5c8539791886923485fe592db014e9d7dfd71236c2036357c7f4d7f633b0fbbe1de57260e0d8c09f0ef0ee3f27626d13f26175a5d66004d74" },
                { "sr", "1ff4fcf7a35e6f5da9a5fc14c589b7efde91bb867cb6148840693bb28da9849f0c7a4f031d55ca5711390cf2ef2ac669ce1881265a5166b912fcb425c3ec567a" },
                { "sv-SE", "332938a069c4b5f6612d21a555b5bf92c5531ed14fc29d063f7db666ab9fdee1e7069014c659de215a8d0164bf6f409071cea3d62ad5632b426d690ffc5fc3c8" },
                { "szl", "4e1b22f45b3c0c30e64c1778d71b688a0ab7a049d2ed93d3d1201f7090bb50261cafe2bb94b16b3691e97a364fa3a825d5ab0308c76b7c3d56d63569bcae9c3c" },
                { "ta", "2f2629947e6eccaf2f12689c3e6a6aec6bc66cef2e864f0911722cc3e2e46067dfd1d2f7bfee805bc7e38e0252d676ac36187ab4992261032050ab0bdf3ed24e" },
                { "te", "73fcbb522c509a6b4d7629fb7505382e80d70801642253c6822286efe991c18668014d0e3525cc00a915a38eff7943f9d57d720a1d6d6803e51ebba8e1d78d3c" },
                { "tg", "a2659922d2d3875033c48e34aababd1105ea49a5d5dbe3ed27cbf6492dd418732ef22c84dd711d0d9e0fbe59c9e2c11b2c205ca13e726fdbeba3e852f852beb8" },
                { "th", "1c75cf85485548bfc857d639377b2a3728f2c7aa03371ffaee73ee9f4b5e8a33a662483172a1115b679da6e9cdae64c7687c6b673245e27173e9870369d08fc2" },
                { "tl", "b6bd2b60889e678943605b13ef9888039780f3ce1ef97034f53a5468b021c994b523fb9b5ba07b0f374b1087da5b7a7ac452756b2ddafc89483db14df1f37f69" },
                { "tr", "c70ba8fd95c1a9c0315fab80f83b8d48c52d2e4e6ee3f8dcdde49b5a12092e9b10b09aedf823f91ecaf7bb3b6bde6c3524727c0ce7260882defade3ad0c75dc3" },
                { "trs", "000350af9bdd6391799f401dea82bc20754f8dbc6ec2cff2def2836284d5b31bafc39133ce287f5c52d5dec6ce11233a3df9a59e91fd8578531aea587b1ac42f" },
                { "uk", "fd0b4dd6dc204a4a56217655975b12f639f5bb6aae64116a954de1d1a77370571253034befd1ab5d9efb47d9d0c7a1429ec7da99f83eccb142d5a40893239820" },
                { "ur", "68b9a112cc4925306b13814ba744a35b8c70564efe32baa9b0b0785b99f5ced834b05822299fc712e418d6caaf3475db4f0cf3b944ab590c7a891fcfc3dcc960" },
                { "uz", "b9b23c988609b12abb57c9e5b476ff71d8450aa0c607f0d77a333defded277691a1e0cad504a42d4b5a105983e61e002e524644a2ca9553779feecd04fc10e04" },
                { "vi", "0acf1a29ccb07fb660a838c7db47b25b6bd2235fe7406b1fb17799b13612edbdfeed9ad59be8bd19a3ab909d901bbbd47ca8785676363d796fd823f6538e43e4" },
                { "xh", "640136b1d91827c92b688bb541a91d05a341843c8b0d1a20b00a5baf06b1a7030c2c6b27164f0f2af044631ba176ba607ad28ce2d555680770b296440d026e38" },
                { "zh-CN", "2bb5f425d3fb19db221365777b700ee54dddc2957b0373cb3c6d55c85b3c4626f3c3aba872dc0afdafb6402b93280764f7bde4533ca796b5e8a973d9a73b0ebb" },
                { "zh-TW", "0a627af13c6806d7a0a3e60d9c38ed16e3c62b9eabddb272734150eb6c17a5136974e29bb7d74353b095d545eed8c12aaea6cf44dbd60844ecc90b4fca15114a" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/139.0b7/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "033c25f16de5789ce919b82bcc2ce74111226c7b0360e67948681118453b8fbeaf9afc214c4304b0d1806b91faa93df181873589728202aa8fe957a6ba828f0f" },
                { "af", "266adda66fab60aee18cc78d1267ea8c9ce0cf0d86d1a6052e4baea3ac419960e6dba820b5e13f63826bf08db78ec5bdaf2ebaf43614ed7fcf686ee15bf5b33f" },
                { "an", "bfc9cc4d56f132195be70e85c4241631edcbe15609511b67750943e89d005a53b7349c205da560806de0eb26b4deef2381d0fe813f802960c78890bb9ccfa03f" },
                { "ar", "1d9b6fe202b65d9b290cdd71752d7a6fc0cb250aea68b7f50b7221a2e348fb9fa2d21e01201199236746e1f5a02fb8ce67bda89f15d058dfe1bf3c98f9680de6" },
                { "ast", "c3e2e88114dbb05b5f6227a0b41f648c4eaddb7d0dc02f976448f9ba2ebb284b46678a4ae0472441c08934c79f64b6dbcea2beea9692fbf853f097658ee9c416" },
                { "az", "810a259d37f92e863b6c7e3d69041fd723cdad6a8675f57303a70d4e85b56b5857c25add2061433ebbfde01b45f35f64f7b8f172aa603c43a277f023207245a2" },
                { "be", "5157026196303acced2a3b79da7c9286d790f81a1af55cc9175348a90c0edc783ecd550bb3a9b756cafecafada57f3aae589d32b227d88224ff91afccf96f9f1" },
                { "bg", "235965b1c8d0d25fb37238c0722d1db7b3d3a1035c5948f69d497cf9f93ae19916915d11276526d96f266a6b4536ffd6936eef7cc34dac7cbed043cdfef0f92b" },
                { "bn", "1fcb58d6703e43d605e195c76715d20eace659bed343b5ee321eff2da4e84ba722ffba2bef24d2965ced99a5bd67d4bc3aa261ffb5caaa1693fc3248ecf743b5" },
                { "br", "b65b4b0da1eac01acaf38df12a60c2ad9b1b2cbe0ac0407d42deaabb53526631af5beecdf07612a6b2d364608509dee92ff193d46436ac6b1de535c548ffaeb6" },
                { "bs", "fc73de0a967eb344123f2e2586c9d5f6f34ea0ce6204aef37911faa0e0281be2f13f00745ef3d4f1d3556c6cb0671ebf9cfe3253219bace111f1a5647222c993" },
                { "ca", "9bdd71f5e8fda4e835c34d926b9905fa2347638b922b2616cced7f7080f65322fc920df514fdf54a88a6605660feeee0897a482144075612cace72ebb7befdc2" },
                { "cak", "f5902bda0e36a6a63596bd5824b29ba73df68026136e7888daa7f65b3760557cbdc91cdcdfbe699291fdb72d0d40cad973d13eb2f8a4602aaaa64c6081203206" },
                { "cs", "31080fc96121e00f283e758b085253a3eb036f5aa6c0e491958b0b80f8a30957be47867aa10125c8da61a4cbb56be299048cf76219e663ce59e1fc0878c890ab" },
                { "cy", "294b29d72f67771d45e32eaf4665690ca4f583ab22cc239c5a4719e648558c64d3aa0d325aef14d95bf43f17ee49d96406b87ac7975341abef27f5cebf22c737" },
                { "da", "6a25fe037bca5a31469a1243695d3c32c3b66c070dbeffa5ee6a45e3012961d05d7ccfd980cab66c530e407fb4092a454e6fc7e02dba844dbdfd2f6f64583be7" },
                { "de", "a4e23b55da39ecc71cedeb0385b5bb16735fb6e4e6e50255c45c09be2fd07649e8673301924686d2d34a4f0e1141539ec5e84a57446f1b685a3166bbd6cfe639" },
                { "dsb", "f50e66c662d2dcfc631c3b7bfe1ab38b88626290cf35ab8d87ee000d6a445332f29e84d34f2d4fd0f81b038d7f80528b595bebc312228c546e60626b868480e6" },
                { "el", "a9b22c4aff6bbc9d046b55240815e84d59c21b006557bf7ba5acf9fbba03c6a2f736847aa7ca63048ca2c75d9c71ded3239bd3f626457d3c3bce6d2282aec584" },
                { "en-CA", "cc2b895de416322d3fa48187e7c3eb48c2bc2cc7946598ba896a583cf5693fcaf1623901f31d66ee48c5ac54a1cefbeafad565097f9b9492339127aa7c8fb825" },
                { "en-GB", "fd969f94bbc6ebe3d4ca722e19f6eca2216ebf6edf5685f49db113256ab3980795a63b065cc221e91ed391144591faf28b0776e0eb9df55ed3c7dce170990855" },
                { "en-US", "e513847aa9e6961a51ac763b961ea20091bc7a353049504379532f36326757fd4bb17c7c8f481269486d75a52887580832443478717c18375abb34adc85d7050" },
                { "eo", "63406b625a8feb062edd41dc0e9226a6c61cb952654aa5bdd944df19853df1e9b6f780cbbd55f1b415223c8f3564b8af1291690495725561ddf42fbd8a123e00" },
                { "es-AR", "52300be5a08d8ddf1de48ed83a187e80697daa4d65208708abc06a9d98793e58d06206f14e8dacbde23ac7e8b1473ba7af5582bec5c0deb2b134149f4cd8c552" },
                { "es-CL", "8887dbc27d06a2c00d09c155f015b46a22fbd726aebb64007a0621a1ca82609169d57e4c264a127804c8868fb68e6454d597e683acb175ea55c493ed6bbf102b" },
                { "es-ES", "d399d9d6fa8f63bc350e9a9d590dabb5342fe4a4a66e45adafea3006f4d88acf5b090d7c0bc76b6b6044ab15c022e54fc3df2768c279d1738e30012ddb87cb62" },
                { "es-MX", "f3639af99a9613fbbeae1dc31debbe5b43fc6d5d99d6cf710af11ba87315b39591f3c58a56705406d5f6830169e8f1b72aee5d1a0a2d3d9e679647e1a8bcd404" },
                { "et", "aac061e7ec1eb4c0d246dffac5daff9253667365f35c5f0ade34dd92a9cfcd117d61642c96bf953fd57951b0fdd3cc241e861ca651bc92fac0800e4dbb0f5c3b" },
                { "eu", "b50a7e76f55af7721de4c4d3e78f5d884376d7c8cf4d99b614d32ab52623e6027af4f435df18ae249f04b1fbe8bebf695099cbaad3d899ff27d0605485600986" },
                { "fa", "a96e4fe5a97eabb13ed203ad36cbdcf3d72cbd3c7e006c7c5c70f804a336a139a049482582064ac4779d4f27a511e4d6c9ff4737991489b9dc1da3dba50b0dfc" },
                { "ff", "4e75860f1385df21f83c1abc7919775ae15de7b0cae11e02fd8e5020f2ebf8e97de679c69c0c571d1342d7bf31eba7693b1f593dc3a8101a3d09e62ebcd7b1f0" },
                { "fi", "64d4a65568b258c7773ce0a4fa916afb8f4979d33bf76f4d9f1a5a5700de6d76a04c2bde4c84bea19c435e116456384d9ad5cafe0590cc2713abfdea65d13075" },
                { "fr", "cb8bd9cb6545900dda586b38cf66438a226d015f3e993137038f1b40ba345dcc1a34aef75707405f6d70f1df4b4c746d0e747515773d5e9fa199f43bf88ad9a4" },
                { "fur", "0e2be9cd2cb7cdd488bc12375dc6262d416a1f5f124b6c891b500cbe5dc11477ed51b2bb5c5d1e7d6a5e740c9cce3cf4d801c512fa99264e2b3add0641f594aa" },
                { "fy-NL", "4c840fdcfe9b3d7872804f1a99b838714e0ffeec67f817f78f96e65b68b292c2a8fe3af8a8c51f2f8f10b3fdbe1e4d7b40e6fe6f05b4592de89db22aec294b31" },
                { "ga-IE", "4e215f0f152012efb5b8c01df0c2a50f4ce6f3cf9c2c6b3e1bc8dfff5d04f414477c02a45179d7b07965bea8596a8fc16ad89738f0948ee673be66ae1dfcca88" },
                { "gd", "58ed4003c4caf1a05920266b17d4e911ae7c49ef2276eaa944cab7bf05b50192098d1b62dd65d71c72a271fdaec27bfb8e5ea79fb44a51594e5b113af413cbfd" },
                { "gl", "75a1879178a75cb318e62d1a258eaddbb49a2bb485c6fdff1d0e8838b3572d613b067324066cf2e7bb888b4a210675c2de4816f8c9320b0e758c854a632ba79c" },
                { "gn", "a7c1abcf9964f66aeb3b4007f94a21107222ad146fcff4afaba6899e0efc57c8b7e50788d4b97a6ce57f0f335839bf00b6e73c0cd215b7ba52a5154fe2afbc02" },
                { "gu-IN", "aca8384342c3506fc7e8b667d1c29e3c79cf762b2e5cfa7e4db62a00a697ec05674cb259f69cd67957848895aa0e8ec7006ecbe9262236cdfff4180b71f2f257" },
                { "he", "128c01cf246c5d41ec0e285a95a1bbd77c04bfa372672be8a060a4b2d1336f3e9f4f14a093928eef933a873ffd2dcd3a3d42640a4b6333c16275e4cdc2548938" },
                { "hi-IN", "0740fe597ea0f00cdcc78348e08d33c6070be49799773ce5ae666a1d6be30c8bfa2439579cb38c239795a9a69aedef793d736633dfa7d6eaa83f4179fdb2bf07" },
                { "hr", "33ae62102a76da6411f99112e93d3f296d55e4ac999433998bcffffb39fd9595dfc8cf21a1b4206119d8c0e9d86139e8fdbea45d1e13cfb127ecc5153c553910" },
                { "hsb", "27f0f95209143e1a90a3f58ae2b3f1d1f0277733f44dd5b58f395a6c70bc0db465f7884c8901b2b57357691e093b3bd6e560841b25cd63a9ee98c73f1959525e" },
                { "hu", "c2b4121c9007046a6b14ebd7cc65c2e5280294241c8861ff0031c4f1eef64963b74dca1db510fd7f2f3b511753218ba48b0d7f17abd0123c856ecf8c5ba77353" },
                { "hy-AM", "eade5b3558e1c13c3ed37350d7c02624ff7e19b3e003d172d2011fcb683e7da0ab49dcaadffffb1cd1e77ead130d3bc9d166a8c83e0c112a63ec79616074bf59" },
                { "ia", "c22ce917137b6be3c46278ac211f296d687a5e6e27a8cc5b43b89ec0e635df3a04033ea577e446a58d84fbd003c76f80a722e77a2ac2837c630b3b55b967dfc6" },
                { "id", "7211c81a504cdf1702ec557b3a5bbd571be8fef9d4f9a28a581880f6fede4bb2087170b2ec22e20b6ca83aaff157a8fcc182ebe6565fac1cddedf08861064a5f" },
                { "is", "6355754957b1c82740fc17ced4f1d54217a7a231c3e2265aaaeddbd2a67d9f3c1d7ab959605c8e4a5596d0ae144eaf588dea95dabc7cffc9cf96f16e625114dc" },
                { "it", "95b15348944f7729c7ad7fb2bd378106db8c9f637a8795df978156545cecbc4a9d3e0bb07a3c630706ed149e337fc08447b19048d90d7a842ece2d967da96479" },
                { "ja", "12d367cdff25ff155f034ad4f209cc011948367262b90495081919a6230ecffee60d411531afeafc80478512dabb0c912cfe571236887df484b21c2e6f1674f8" },
                { "ka", "3c2d587bb53d5e92a9f746318bf89191151080054bae7ed8b00d83db1659b7aae95531d102d8c03125127793c2783c19fc628ea00adfb186bea98fad24d4d673" },
                { "kab", "6524bdaf522fbd110cccc8f319b65f039c45241c863b55bcb961cba0b0c8fae8ab7cd89a3b9e2ff1ff779aae1e38679eb289b500f15b8a3db785a589153d6e42" },
                { "kk", "2629fe04b2de21e3d36586766b17faf12fd2a8664b60582bfc2efefea159d24b54a855e441855885866f0fe0d3bfa9b7f953762a9db5f5a29ca072c16fe8eb32" },
                { "km", "4de5e0b638bc26d3011d109208804a2f60c198fa124e22e8a206fdb456f00a9d5a3266fa865a465c4602a437ba43a6cefff4cb1cb0ac8bd1ff9243989141d318" },
                { "kn", "af68d7b7a180ffdd3530fe0a48e241da93326a289fce7cfdbe8bf51a871906869fc06186d17423c8ef0a1430549205dddd4e099b7e7b28046ab0eee85f8c3c84" },
                { "ko", "6f7a719214355c202c4b2836e38f72199808d86f9e7eafbb205608c4db1b3234af41a3344c77ff7bac9da712b1e91582dbb4023e64d712fd7c991d4a4b6d2eee" },
                { "lij", "bb5283589ff44cfb5b682a1bf6a17f4437eb48dbab3f495a01a79836fcf48a17816e46c04b2b5b5b9d5489059e877b8db6a8355d87666b5f1229b273ec47361d" },
                { "lt", "9b26af17416f0928fb450fa89706acde90a20e2e55c0698b6932261bb322dc2bd575917728a8b980ea8d7357e060cf7a68e5db43e2baf2d591486149aae0a5a6" },
                { "lv", "cac079a81de848460cce6e7b27e91ea7e1af0db499890124ea24fc92ebc5eb1146f24542013da8c4555fd9d44e879ee1666afca45b6e2f260db055ff26a38ef0" },
                { "mk", "3af39989d49d688e21475be39745adb89f45f08184415bf935f1b7f4d835dd202e0770fd755fc3a70888344156f8047d543803f9c876163b171baab40a62b156" },
                { "mr", "7de82c57e6f0aa518b61016a7cc4fcfd416eb125d2f01bc94eb4ff728fabad9adfaf0fb55091b49d2b24d46ba09f9460592fa72f672a1eddc64471ec65f94dac" },
                { "ms", "8837822c062bc0cd5d5eac46468805c4d77d2919fc7906be8284a99fd13d142b0c1ae9c476515151784cc8a3d21a3b57cb7f5a5037acebca57eb69de0601fc97" },
                { "my", "37ac0c702aaea9a982e7774344ab1d531a86f9d3fa173f5411fc1d1afd306d97f9feadf441026d0e55f54b9a99281673cabd7d5b90803e548aaf6b3a6759b968" },
                { "nb-NO", "493e9eb9e10216fa2ba06f7f8b0bbc973321acc3ff1d1c7e62fa663ed695667d4952dec3b3a8967c0737f1b4f4e76728e0397a0b30c99530292c3d505737158c" },
                { "ne-NP", "d0b52b77159880d4d7adb76f52bfff391abf2bda6cc47199831d491781e023f1275601be4717e4ff808f41af9cd3174f69d98387b849aff66514f75dd973e673" },
                { "nl", "670393422e9793441d24afcb55d46fb66e27443ae8a4265ab0314c55355458a5998479d66ba1cd4262455b018ed155e733bde539bdeb67b52e40be46fcae23a9" },
                { "nn-NO", "6155d4faa60dcccbfe80ccd5fb2ff3509243787ad7162f5bb44c8c4c1ec3339683c06252e5d4ec84ddbf2d24b39f470ed620752d1cb29f459417f4f10fcb2b79" },
                { "oc", "0cad82c8c89d1755781de40d98b3307d70243a78451707c51f3d7c8260a979b0fc7ef730315e6e10941e209407b9cdf02cebcd74b924342fdf33419af5e02e71" },
                { "pa-IN", "a99f5ae018db04bdcab53c078c29efd67fa91cf64cf0baac348c1da0c14e43a648824f2d4b820ecf2167790810eeec4450f967c7be66661b8e857eb5505f5524" },
                { "pl", "8c10bb43d8ad0809c952af19e098d482179bf356e182696d68d3c16536259580b60bc0d771ad16cbab06984c45b447cf4be93a1fd2818973dee3c89679b8d82c" },
                { "pt-BR", "8e14d1858036558e88fd8f883c5738c85d1c06d0e5f594016a2457984217c9b758f47d5b00e20cf99d8a894c87a9bc8734b372fb1d2f70fb0a5b778affdb6ee7" },
                { "pt-PT", "c370d8e16718888c4ed29544fdabd89989ddaf703456d3971e42a73484e879b0443ab999ea67010493c620c89db38d54a097560d175c3ed55355a7d041018eb8" },
                { "rm", "0c9f07c1fefec92840d913b23ffa4100c1e8a752b8b51ef39e98b70565c3a90980c2b491286b383d8e5fb82afc77c8bc6fa007ad4bb45e751236d438951c923e" },
                { "ro", "4c9a4bcf180051d3f272d78a17a18f84218ff4c86791d61265260b7bb94fc627d7a5d3d87b5597603374f7bd48d8d6f9eaded21243f47de22461aaa9ee45e433" },
                { "ru", "02e13fb3224fb19f394877d81ac30aa5f5392a23749ecfbc07c0a59877947718a21670ef4dda567f074932758b8e5b0c14ba72857883d88fe324b27f133434ee" },
                { "sat", "7ef2c1386d9f23b7426e085b6b4f66cfa7bb6d3b33a14a62493ce5d0010f8f7db5b15ce7eb6664588b61ccf3da39711814c658e7efcd95f1e330e56523282e77" },
                { "sc", "cca255172d9ebdf1486fa3fe670b0a5999431c456f73353fb6eda1b555e506e2adcf738fe906eb0288bd81407cf7bb5c7d64d69327a0194a90095742bc56119c" },
                { "sco", "b7f6fb0966d865f231b86dcacb4f89f1bcdfdec0aeb56199a34e0209356d2d0eebe16508565ac4cc162d9e2330c0479b7b4b0b9705f15817433882a87d35cc53" },
                { "si", "25f68cb74bef565c3a5dcdccdc8c223235a79c0abe250b9838a626ac4df40c7200a991d7395d88cd270dcf462ce7da2a7fc7a3bcddb168e504eb60be4c701e5b" },
                { "sk", "cbb3f1dafdead838f35f729189e2ffda01a6cecd5bcb3a5f3b4d7df601dee97a71e62c0a5fcdda392480e2e0147f82c90fef478771245b1022461b78f304f297" },
                { "skr", "2d352f515bd9d10ba81ec2723f82c694d66ff091e58142db98afb0d703b4ad5ff9a5f979c283a0ad02d1c8d461129a7887d2e9934961d2b834d3e7b8918d0f1d" },
                { "sl", "ae50360899bc18ef19069e5b9a25923798f980b87833dddafc4c2f811c0864d3b63f2e8fbda165c54d2d85c553bb28796ced7e0e1a393026250d33a42ff5e90b" },
                { "son", "dc9f15a0606293b598b34ac78ca482a0e532b87c49d37ee930f2dcb33be9966126ff0549ced011e9cff54b501cc6cad53c1605eba2021018173a83d33b29917e" },
                { "sq", "bfaa8b7442341d8aa090eea01af8e5e00bf225eed1db8f7ef2e9cd3152c209d29291449a5e5bac6f50f5919da0955cf4a3205db4d92a9ec8965fa40743641a20" },
                { "sr", "b33e27ef2bdefedf8803ff6fbd28cb90ebf391f1e2e6ab460f17a9b321b98dea1b57b7fae6e82aeff3496906931e873700cf4165402517c38e4f6b598ccc7911" },
                { "sv-SE", "b8ddf02de340b346175fe0fbd5050b0798846c73f1de7439b74b00fef2f20abd04001fd6bd9c621d33d5e34838b74bd3a7c521353f7197a4c5dbfec96cb10f9e" },
                { "szl", "8bf117b5e752e651630fc27033db1edc4de613458281ae1730dda661b22cb865c037707a67f73a15fb405d605298f8b814ae2d3dff353fabed6245ba0b6e055d" },
                { "ta", "bbd6a324463dfc496cd75c7c23450e52c0b3f43b3ec9b36b6b886296a7ce0e37dc2e0a951b96099046d1237a36422296b8430baf3e9246fadefb1e0293f762ee" },
                { "te", "c322dd42c00a621e6d1e2847cfdd396a6ef7ab3b49554f3fcc95cec8af9ff55cf14b800e8645fd19a9bda0cc148a9c72a36ab485061268ccbfa14b763d374c0a" },
                { "tg", "8bf590277f08c4b53104806520843b9fa0c408eff32b6a0e63d398e8e623d1d2fecf22c339ad20de119a10507ea8769db2bd9681e0b36e32416ad2e7a4bb2b38" },
                { "th", "f3091aba8a91b6dd35545febbb484e3000734165f9819301136546b79208c988064fa9ce0085aac2c9d22e4317ed78e4922c9c8d83994ac4d5426905a3c717dc" },
                { "tl", "85dddfba05289e001f2f2a2cf6603bef5bb6410b6bc895b024b29b02eb2ee0e2c1a100664da326066f52e6e9a18e6d8e671d74e7c573d287a56fb5874a70d4ef" },
                { "tr", "a6ea5e330beea6106ab61fe32036222eeb1004166bf8fd8ed11747db52d522f259aec16d872c83af5d786ac57dedbce5029688fb5e0e53e367f740b4adc7c5cf" },
                { "trs", "02c1e53833f310cd78113b841cb3b1f3a96bb4eebc374d56b33f43d9e720738aa3fcd810d454c06a6cd5d2503a7dbfbdf80ff576e305ef2518b0829a1f1b36f0" },
                { "uk", "098e5384b8e750df28d0380fcf9a76870170171fc3d92974b601a4190d003482395ccb63ebc7065393916bb96fb4e2165f66cd2ae52068a9cd1ecfa613878fb5" },
                { "ur", "97c7165600e15acbf52c6157ac3f7c41f0d466eed77dcc75c8c85b92c5232d578281bfbdc3c57cec8e9001f2be95be910d392729e14c2617377b97b30092a98c" },
                { "uz", "83a4fc365d77737c7a34a651668bb2ed6ea58bbf6feac55ab1d56131719c9c988d8916816f9db6432fe65893f36293a8dd73c8906251ae83daed2e263ddeb488" },
                { "vi", "54cf072ad045f70375e9371c4784e6981b3a47e73ec0ad574b2fa1211206a99d8a4cc4a20b87f08b092cf0aef9fd7a3f08ecaba97056f6ce66216e8a576f4e26" },
                { "xh", "a224c95cbc9c060940385ac372f85db758a2ac04e50b3e8d078ef50cab274e95d8088d08268d19e8f6030c999ace0c8261041e10524a565be3dd02d164950a41" },
                { "zh-CN", "dd9459001e3cace7d31e777c841b4947e6721b5aaa92cb4ef1c8e6c91ffb10db70352eda7f48a9ce665a1ee4bff5462e073f5e6380ab657ea0568a7241ece37a" },
                { "zh-TW", "e4457a643f09b6683264ad92b8b6027535b4ca747891ccdef41deb33cac474140fa6078e30bc1f27344cfc79cc4a359be46b23ca2939001b79acaf591f4f3155" }
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
            return ["firefox-aurora", "firefox-aurora-" + languageCode.ToLower()];
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
                return versions[^1].full();
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
                if (cs64 != null && cs32 != null
                    && cs32.TryGetValue(languageCode, out string hash32)
                    && cs64.TryGetValue(languageCode, out string hash64))
                {
                    return [hash32, hash64];
                }
            }
            var sums = new List<string>(2);
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
            return [.. sums];
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
                    cs32 = [];
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
                    cs64 = [];
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
            return [];
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

/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022, 2023  Dirk Stolle

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
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "116.0b1";

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
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/116.0b1/SHA512SUMS
            return new Dictionary<string, string>(100)
            {
                { "ach", "594e675911ea74dcd69202bc9b762141e52a63836bc39d4cda27dabdf5a058bc513ad2a6a03f18d1d4e96b151a52c9ad77678dd81a50806e173b377a340e67da" },
                { "af", "d414405ef266407d21f3eabee7d4ff0192fab50dc4662ee27b8ea9d5802c3a1ce95296e0a02bf4f48a149f91212637f6de9fa2e5b10a4ae28a22d997285b0b86" },
                { "an", "11a21c3f07d9cfd2e17cbcdb112e24c9e92799019ef007aded8d6ed3b412d58e8ed9dcf9af7915ee3422e4a6108d26788d1c8805b4fdc48ae79040375212cdb3" },
                { "ar", "3a612858259b23e8b84e33b5f01505dd13640a1b49fa47dbee0405913c8871345c7548c5b8798304b98ff4f471a96ad8cd444037d32f2cb4616a1ccab8d91743" },
                { "ast", "67ce101463ffa8bf9f4730cc9de55d67d9d1832ccb6771e099c6b7a2be280bbe2dd0581f293ca6018a8c4937e97ba08b0384045d59db32b104622786e6071162" },
                { "az", "efba2e8dda912d35b4155a8fc87a4f2a29d55b6bf737072285735c91ad279f8656ff8d8b1c07d9d3d6b35bb84b55b203f47e2670241715fc6936acb1b0d79324" },
                { "be", "3bc5d4753a68a9c1f78ff6e7706d93e6bda73277bac25173493b361e7073c48e3a67b177925ba4d5434c9a8b845d0cbd2aa9a7e3bbe205e6017535493de59a3d" },
                { "bg", "9f6e302676420c75eea146cd79e9e64cd945ceb988b481614715750ac3a747306670d57bf7c56ac7e58d91e84f5344297e5957a5a38c1055aa72af99ef53fbda" },
                { "bn", "9702051d360704bebc3770bd8c83cde0767699115b73eb15e68fb37a2d6c036a565de5509c18138f9327bb1b2823f54c63b54a336da2b60fecbc2fe125736673" },
                { "br", "bc4b78559f9e52816144dfe00c056f49ab5e6049cff03da7ed43208187371cb50b2fc18a7d3e7edf96ca065e4b0a72932a2b90e3c1b4e3d263329a7cce568390" },
                { "bs", "090c6707b2db81291b310f3eb1e8fc8108015ee89e22af7ae290f6e9ede88e867f44cbe51ecfa2ae53b3b499d7cd2e89702553c06f8f8396428c92998b9be79c" },
                { "ca", "48babd8c48f80151500c0007af244a1be08924540c1a3f2dea7558fe072276998a0814efbf1d81d94f2f24dafef186a202696760b8234ec21179beee33f35519" },
                { "cak", "859412403c8bb8d9129b08cf5aa374889b7631184534d8c83e3894779e43dd3d791517d74c883f2d9b086cbcd6bd8f1b13ca2180a19ac1be19e80869c77fa2a1" },
                { "cs", "4b34a6d37a27f4ffb2702ea7a21c239aa74c2e27c431eefaf69a84f8cd164db9ab6f45ab47623b726802a16130d8566514f07666200c43a07a27b3a7025c8579" },
                { "cy", "a2fdf9d507c45c14952cdd43e0c157421c2a9872ec573da03b3faf8290b3cd30c0bee3ad41e4c3fda78c688f17e716a2c75943714402c3e0d2e242b79a63fce5" },
                { "da", "4f9dcac1e54134e9636016864f4ca68b435813be1df877549a7c82437d4fecc0f82a2d9ea55ea1cde6c22e93fd49df6d4342140e55652a80e0988cf6bbe0a821" },
                { "de", "d80d958b0b0b23c1c6d0bdeac8c811f863ba12214cf4e9dbbfd4a30aa6e3259ca74e02171d4f979376205cf64d32d516262aa2d628dd68527e3446bcca88e34d" },
                { "dsb", "ebd76d21a46f193d7c13375fc8a5e2cb8b97d7bd957c1088517c7bfaf382765566888ca941038372ed8991507999f6bf7ddda6cc5c1397ff241eef5822d23b2c" },
                { "el", "a4199b6e2eb516891c4d60fdbf12a1fec00aaab45b051376bdf2d9dd166575a2f5fce307df0a88dbbd32bb766cbaad95b9c9261c05abf5bac7b292249241d6ea" },
                { "en-CA", "3fb09cf93e8c9f1207341e3a61df9bc1d4c1a45c119c65890bc1353514c71be80c180e1d9a42c6564a98e81cec19bcfc8ff27db8d30e27fe23927e3bcf749081" },
                { "en-GB", "8f43f41427017118c4a4a12ea0c7802da29ad1d96899d775202ca644424758d82f6116f26bf4398cbf6ad1cc55939ba0f97fb8129824cce6a5aeba5e4decbb3f" },
                { "en-US", "c08ca993ffd00390658240a9481fa2d5fc2b2aff6c737b0ed8870cc8742ac82cf42160e9ac5708d9ba73a18f37dafa573021e5a7abe49fed6ba5cbaba43128e3" },
                { "eo", "f89c2c933edac5ed845c7cee74c4e104f436012cf65fc9cca97b2e927945d590cd9022696c0fe7eddda03e68aadc8bd19ff3f13b33a4bc003f4fc7bdb33a44ef" },
                { "es-AR", "9002583a245b1697f8c276fd70169c1b9c834c7846c021d45e3c54f216b9c77e10db372d0a2fedc42e28f7549326adf30d2579c24be3a74a88487876e048e8a1" },
                { "es-CL", "27fcc806d405d2efaf5948d9a1f4f4489ffc085da8b3ca449ced79b3c18f4cb5d528a425d17f14ea1ce3976e587e166f04ee920a7a817711da54abcacde9c237" },
                { "es-ES", "8992459f02c3874a437bacbf9b15d4d91433143a6b7fe1911b3498e5b28c2f444cb97ed660082e6add0ccd160028b1597aa3c9a3235bf3202b4b1db8c71390f0" },
                { "es-MX", "d07463672b79e6d3addfb2c79d9e8379d76d14c4283700d29da1ba778a7ac7ed386040df9331b83c06674ea2ab9a015e4d8e69b10333e0ee163ce194a8de02eb" },
                { "et", "b2e9656bf75eeb44054638ee9be2ad48204ce45e0a45037f52590eac9339f9227a22fdfd51c3525c49767ca6ac9ee0da5a0297b2f51c6270f223641c1691a4ab" },
                { "eu", "7057a28ba3413a12fc99dd5192dddaa95ffea483110c6411cc2edbd8d1c753c78981e7469f1adbc2411d44727624065e40e0fae369e0b117c356fd1b9a8e955b" },
                { "fa", "b7e4fa5e2f62ef528abe39f92a07f558c0696a2995061bcc5ac748101a9cc159901d520dd62d7b64c0e236ea16d45946f87f5af0f19b62b3e7bb0be7b51c131e" },
                { "ff", "e4d3a5b4636cd8de9f9b7dbd3e2ff5e2414a7c6b62070bf870631bcf50790ec192dc2040091637521177a07310ef5653f10e48589701a375f839736e6f1c353a" },
                { "fi", "ad68b768d1693b573f06d17f82a847ca56b9dfb59715b365434bbdbebb6a957b275a9d246bb61009913bd74f2f5fafe99a092155d2011def3429723f962064be" },
                { "fr", "451ab434c2995d6d3647f315b797fadf510f4d5a66be4ebe6d0a30ad43b1681b22601c20adb3181613ab92d65a6dce7d30041fd10b032d28ce64955eb95b6c0c" },
                { "fur", "fd4b6d29a7f2c83402ab5ba2c0ec03805503d36d40967efd29431e46d1d699f03489e940370741530d29db8c0898146614f67abc82bdbb5ba0d7aaaf3800e53b" },
                { "fy-NL", "0972c3b3e4e7239dcbaba98e60078cfca96ba0464079dd03373fbe7e6f620f4565e6b934db15d1475054ce06c7c235d23e253d6c8723fd625e0e5e8fad7b1318" },
                { "ga-IE", "52dee69f532baaafb917a8540277a6672b796c4f9351aabc30d6ee1d6698579cbd1d20125d3c42c988a514f9e7048e30b85ab115d109e32fef74d534136c1e64" },
                { "gd", "b2c53e9d2f4c148cf15280a37ce505c80a116af991e81f5957166563a7c7380d369a368df6bdd10fbc10ae5d7dafb47af7b76a5c8b99837e777a3ed3fb9b89ac" },
                { "gl", "6be21cffbe87c730f7421ea41c974e61e631d16c5ff031da7ca6a9f61e5bdd73b772bdb7eb6acf722c071c4d905d44087e5ba524caa67b55195ced75d414b0a7" },
                { "gn", "7468bd06beaca4c893b251483f51cd2c3f7d86cef9cf956430c7d9235348e7438ac1f36958b656be7199d1b0c3fe50c62a0f9a91af3a4b50fcdeb03fa79ff648" },
                { "gu-IN", "3607c21c4d9451310c13bfd3ba483a871bc4d856e2fedfd411dfdddf8ecd90a0f2d1abfb39c23d6412d3e495085b6ec86571060fcc985fb7c1258ad8a1fb781c" },
                { "he", "db33451c0ec497357a663329dfa5cbffb58b72d5559b517a25a012a2de634e55edf6ec7f336e9c4f42eb10dc056ae705402dfcd3686bf823c7ada7b9415db4eb" },
                { "hi-IN", "441c8ede1d31038901a91956aa7d1f743e9b215f92a432b9c6fa8137d035834796012acd2a5a034464db72bf053bdcc3868dbb75cc076c8e20a723b552387fbb" },
                { "hr", "d8f213bcc02b8c3ea16a6377d29c12b32c36ac0bda50cecf6d30d3674cbe96e560edc4a459a844f5507c96ef23a8178b76a475a59926f25c682d0e381d8bcbdb" },
                { "hsb", "610043007ef1b6b07356d42f4988f7aefd2fddbab63bd090bf109523a78498e02fb7bf2212f705d839c4d01fa03bb3d44f6037e1981892c1a848633ad531a46a" },
                { "hu", "17ea5a4a8fce0ee6aa8126291677f4960f6675f6f574887fc4aba2a52eacc3a46320be3963a5a8284fbc046b5543294863162f8c301af4532cfd263163b662e4" },
                { "hy-AM", "a8eec39b906413a348b067591d9ae8ee5d140a124f380939b26f6ae3f62370908ec75d80ced7c6ec7df6240ffc315e912cc2f83003c01afaab5e71b1f38d9e20" },
                { "ia", "6ac6708471c7a1502fac1699930b4fa867ac0e0f4fe03e6560aa9414aaca3cf9a6bd74a33b61adff03d0af133984fdd820caf183267392e55d1a541277646e57" },
                { "id", "445a4e9342500d2ea2fcee059413b73d6469a96e17fe066505c9bee2164c262ad76b4676c3063626f6e0942de2fb0a59b4e810b45ef6b5566366c1d6b0f56801" },
                { "is", "0e25f7ad6ddad5711124745a404c589df47cff4c8a2101ab5f67046fe711985fddecee4801a39dd7280696c064622714f45aa8ee678f2d3d60d484be4082abad" },
                { "it", "98fd3c8356245f04dc9734d7706fe3017c67ec3b6bd25ea2a8598aa65ecb30a2964fcb1f1f87357c8309b47d4906f14a0523e5fcd2dc1d7a8affa471efc4511a" },
                { "ja", "cb018aa7685d84568199c775a041de924c09f96cce6c94aa5b034ed00073edee1691415d495b3750ac17c58c40541ded199db60b9b2d71bcf4862c5c1e15f730" },
                { "ka", "33a3c7b9483fef6c6432cdb81ec4d5f56d07d02c3cc6922aaf5de880ffea88ac81ae432611b0cbfe7ad22c35457fa645d595f2e9e9a9f15a2f69e4646dbfc462" },
                { "kab", "223a3d912d3bfa2fc342cc2a0dc0a92f09e527c05d6283155cd927f974ce6849451aaf7f26f2a95b008f3d17a27ef45318bcc872316bf951a8cc8337ad3584d8" },
                { "kk", "23d000b5149f44efd2df6c5f5452b047bfc3c6896ee886923bfa42ab1bd1d170201b7972007e8f0862b70d92ffe03359326bfa3244b82a0f56f91110888f6a31" },
                { "km", "e147ebab5437370ba391b3e10979b3740818f2329c235b6d589261ac1ea46b80de7843aa1267305816d5535cbcf30d03515c4fb69a5e8472972978353919e18e" },
                { "kn", "4ed524a5e850b7547be18ce251d5fdf0acfb6edc24e94124116f6d88660879b45f7ceae171d83809c2cf7243b32d716fa968b0232adebd1b9a426f89a6c62aa9" },
                { "ko", "3550a9ce5a81cc89c10a6b4f04c0159b1e11c7f6ba5df53f1d93e2f92ec052708e5d4858847f1afa1a941d66422261b7dbb2da650c0e5e359e438bbba7834286" },
                { "lij", "ed224dc02889224bff30ce902bb85bd8b35b4d52eefd2f5364aa5abb90cd17015e8c79955e3dc5b12d3e8728dcd5a0e370562134026c90312397e2c611fafd4b" },
                { "lt", "b106d84cc3e18f8605db62f06c7538591d35f12e5f4ed7d4cf70573483db72f0444480fead44d2e6e258ef071f9a41781ab7a93064be7ece94066bdb3008ce04" },
                { "lv", "68ca67b035b8770fb7ed74f8b23cdf33e8f36ab86673d2f0750535d60cc043f442c4d364b81445797118a2551136ba6adea7bcdf92f0630d61658d1d640c6dc8" },
                { "mk", "4565c597dfac97eac4a86e9083e5b28c21dac47aceb36ba5912bd11841affa10cbc503c357cd2a62268b8af58eec167586c44fe63cfbadbbc8c805c32f5e8102" },
                { "mr", "6de9d896631ffa6b216f028d3a16449f7de1c12595da772b0d59bd18c6e94098ea4395dddb6eb1a7fccac1306c604eaa2db83763ce2dc7154e609f276554d96e" },
                { "ms", "a79fa6339c7fb59f37809b76f19315d946c063362662d9649a6b279d5824abda025ed665d45a4b77739194a6f35b5caf470c00eebd0d7f908b16192a9c6a36f7" },
                { "my", "2d749d08af9f8f3bc631cdcd648cbaf34398281d5d3a22097ba042526b4ff25e22f842060be907dc4898d7df1ebbc397992a5355567405b5e2271f03dc047afa" },
                { "nb-NO", "35ab4602d0a3cefaefd9951bc31221feec2f2d1276b0e6040d7ca26ea40ca8fcec47fbd1ccdf12aaf4907b2e181281afde12726d5911de03a92c79d5ed3b08e9" },
                { "ne-NP", "1ac5a16e3b680487c02b151670d2e6511c705d39af57140b561820c00be3bb45daa69a1b62b0b88c5894af0e091baaaf3cdb444b70c12f51177986eccb5844ba" },
                { "nl", "53d27b39cca2cce8fab459294b4f254c229c18c09a1497c3dccdb8a2328995930d15de3551f3b8780365fd47b5d5cce0efead31a1feb589422dc6bd8534e7b6e" },
                { "nn-NO", "ba19cbe298cf9de5cc9f88a94a0020668f802d112ca0c49abade037802f6e5f2f9eb7375eee773d072054f0e91a702e67cba2f75c66347067fae0188549a7190" },
                { "oc", "c60030828d9e27a3566a70797361310fbfd02e73cdff30db3fadf8c8ab4aa26e634ec180ccfe7e5e2785e97ab6e697a708b5381f0c93a1a020d3bcf3b4944d9e" },
                { "pa-IN", "fa822cb8e0be490e207e5262674018da20fe122841ce5a4cbc552f5d9b2a527edf3b897db59b08630338fb744509c93e7b72e4e2b4920c69aa6c2e247dbed988" },
                { "pl", "ee6d88334fdb4fdaaa03e431942f83f24f3e4eec1e86ae265998b1dada60dff505e13bbca227c88071f5fdf72eb3104726f4dd3a85e664e58666dc35c1cfb6ba" },
                { "pt-BR", "faa06190d2f58a58850bc0b293f7ba8f06078037797fae85c9610722193dc0d1a346fc19d90209b5083150af8b1077eebae68233d806040bcd2436227742517b" },
                { "pt-PT", "71cc37a2966f600bee560ba8a5eddc6ffb453be74069354723f4c860fff477583ed50d0ccb4e53d6a13233d7f94d72258f0c770e216c10fbb7b3a07029a0dbf1" },
                { "rm", "9a31667cd250b8019cc3de644829f37470a82b00b7839d1e1150371d640c5056153915aeadb12bf797a24afbadcbfaa67be5fbd49d4053fbb0d46a0686d21e7f" },
                { "ro", "c3372c0cf764c2f08ccd4e1308ace626af374c04d2f0ea2ebf899bf8b838f41c7c5219461b49d753f91526ec51ce38ab314ca141a8f22facad24f77438b03e8e" },
                { "ru", "6ea73e7ce36cf1d3977e502c1887ba9d58ed94af300fef067c5f79b30290a4db358e3c71d71cdbecb70b1fea7be4899cea1dd0b4a504785417c6ab82714e854d" },
                { "sc", "edd4a757dcd9968e6161466bfd3b9b5db8809ee06ad9c8ba7b108488b937f9a89dd83a3bc8262dc80cd781c288e92c35e9c70febc3743c7b88ed29a73bcea168" },
                { "sco", "31a2c6c33fd53569b91a5f11a073e814b76ddb49ac8002d8e9643394bbee7cf30b1c6cd1ef249fb795b75fbc4f85e43648514d74fbb7e3cf3bc82215422a73b3" },
                { "si", "15807685aec1283d0dc48d79e441736de2b9a6fab450c8bd370165aaf7fa6ae8c741e56feb5e759bab17c6988048a8b0005f509a1132359a35f931f8650f9df3" },
                { "sk", "877d361b51ebf37e643f0e9cc905e2bba5fe8d494be27bbc9b2ddfdb8fff3d6ff6e6e4bdf07f00427fecf1db95060a7d3171d102aa518e783d058aa15264e66d" },
                { "sl", "aa669f2d17124cf714cc160cfb14887e720051e54157f04b5e58713be447d9674775b1d7b5a4a805bd1b1bd9d4bb2ef495afa8139e680782b391d74ec5804f35" },
                { "son", "4416af990e016432a938c111777b1d1f20f05ef2a702b65cd9b90f6503e80106ad6a84f18a40308bf0abd341ef9575f08927cf3b014076a88bc41d36e3c674f0" },
                { "sq", "51774795d8ea2b394019607b87640a7e1d0953f4d0d351a54d0db1c1f5ffb602e2d848406b46e8a3d2168fc78a7d95fe71a8f3aed11f8578deacc6ceac81948b" },
                { "sr", "25edde18466326976d78725ddc99153fdfb83077eb85f0603c3a92a9e589a1889c0d9f0ce37871c066fadc0a50305f0aaaaedea8472a82ffaec6f776757529f8" },
                { "sv-SE", "ba63a3ada827250341cb867b06f14f142b0a91b51db140a60db5531e755bcb6fac272183f83866aff066343374a0752f0aee1c815b6e5a4a178221999e7d7aef" },
                { "szl", "0df9236aa8ff08e8621fd1c77a055b8b97c98ad738bd836ac7907deaeac37beb2f4b7dd7d5193b95b7643acd774c6c15080ff80170f4281eceff1f3dae4b5736" },
                { "ta", "7856397469f98ba21e9ce261010f7df14fa1887ed238fe39e1b4064fb3f2c4973a71aeee4d7c8d3d31036b2a79dc7ec6baaa07dc612c55397261a877dc25c24f" },
                { "te", "9f24651c0daab3d09bb0b18f263ebcc50e73247637e5b3d66babda36f3a647a3e3f3223e3d47c1b52a5c59abffbf1316d14422af85fcd49d0034cfc5e5f8bccb" },
                { "tg", "3262fe91aa01426b4303b95cf2765678b6ec14deae6f84d01ed25437e4880fe7b89997d70b251afdba92c11a46a0388bc0c67404975dcc5a03e2d60e298c03de" },
                { "th", "e79895dec594d15c17dfb04235a2b9d50506e89b63c5298f097580579ea0205b2a4ab2b9cadd2ae5f04704cb8d12e2de950bae6f44f09e864d4b360ed024f875" },
                { "tl", "04c7e9af6416a0c2af4f8a2a9f1140cf73c61d88174cf0c49b8028da8e1713dec26e282ded8b8923f1264b0bcf9c9e1ac3670a4f3c62dfa859fd1273753b2ee2" },
                { "tr", "bcd7dd8a4de9ec45406429888d7afe12fc24eb78ae169b11f64d1cdcc1c93fcc3fdad01ab38c4d91bcb762910823dffc960bfc27de2793242c27cdf4dd7c40f7" },
                { "trs", "bf4494cecb5d42d7b9b449479b22b54c579b658948428bdfb39458d00fba1da6f748911cba02c626376fd6deb9883b3488b10cb884e5a9a0ab1d4086376bfa56" },
                { "uk", "f61753bd402a6846d4c4258d38a38341842d999f27cd661d014c5acb4467ef3d944c0e0967782e204ba12a976d98f50db2debcff895edf51fff5725742a9383c" },
                { "ur", "19ae5749d9ce6b4c8f35dd74bffaf1c488a8a7b02d9b55e8347e24004299a520dc92137ba149acd3de510bed3bf7e62ca3f460cfa7ba15935a35fcf5a4e165b2" },
                { "uz", "3ebd95ea3bf06eea51e3ec038af8e1e246ba5310f182a868e0f82260e21fe42f197c4972d5f83256d8aebec520b13f37be29f8a221afc38b862d7696fc629a12" },
                { "vi", "eab14f1066a46299127f1bc19bb6b84e27706cb0d4a0c45a49dd68bfd335033eb2f92ad4c378bf6a05c2fc5681635c141cec7abfec722dd67e5d426407c96cbf" },
                { "xh", "6c018c5688abe00ba58c6f12132992253e5b86c70f42df6ec9109930d99c49d46118edb447e5881da3a949b885dc3788bd56e706814d3163c93371a0500e8741" },
                { "zh-CN", "5579c0601ad29e02c6d1957e3dc2b77e7a69639a9e941e3a74813fbec28f0da40ab69f5aa1cb931d8445277c98e23d17d05ce344973fea8a32ea1795b0320e5d" },
                { "zh-TW", "2fdb4d4641ee217089701ee0b18563be706896fc4bffdfda9221738235c878b8debbb968ce5fc266b94ebe35d156739d1df89107ddf0c0ae56439c697b5571d1" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/116.0b1/SHA512SUMS
            return new Dictionary<string, string>(100)
            {
                { "ach", "c3c9b6298c02a2e4da6f5ce885dbe133f40b3bce2cdfec9152660d1ac08a76bb26fedd56d9c5cf875d9a1f3fbb8a3e44ac08b3139e48d2cd653af0a568feff08" },
                { "af", "2a6cfb863dbffec48392ce1016636cb177a24a434f55b0b307e8b3760ad8a2361ad72c4dd8ac7e28146e9457e26d8a9db027217a22fbb92e6498839d9ab8b440" },
                { "an", "c6b5c911bd258216b2cff7d8ce508850d3b19903f1ac31967b4ac430de1be6d9beed2224407b1423b0349d79a8ddc7bc189db63c483aaa9d1f86b360df39383e" },
                { "ar", "033655ad9528ecbd879b1e14248a98d86421501f49a4b0d02a057b1eebbd3db936a44f6a1880f956f9567c7569cf369c6ec99182e6ba9a61ebe5b22dce3c3d8d" },
                { "ast", "5af7521da3c7c3efb13ef27d6d66c31aa0dcb752ccab5bcb24e94665cfd857657ddca3f7c78293b8bd6093e22e5057b48a45013c1468f0506b3edb71dd9eb89a" },
                { "az", "d060e1b98a99ecd103f8b9c9aed66de51a89d936bbc181b08236f4ca94ab96d860d5b5784a1d37e88ab0dad18530883b0136265f5d0228dfabac2ec0317c77b7" },
                { "be", "fc18d2848f08a4b60094fe2554f39f3d0c094bd0ef3d1aad6ee396a122804f47629e0cd57db3b3cec73dd3de8e0fdb54e0c303989f8b7d23e0016d09b2e8ae12" },
                { "bg", "2f41084a862ab3039d6eeecd75f5e80ca7f0bcfe5e19d438d90926fd87370766f1dcf4f16329e0050e812c39cad8f2e444088ef21cafa242ea175b5ddf8b5711" },
                { "bn", "8be6d42fb33d2418c42d50ff798d445f9dcd0cb3f38b305429d74747993968d0a613bfd887c2d4ce552c91047d8f46691642cb9c5d5352024af67bad9a147ba5" },
                { "br", "3551e7d67a3df7d861c32901f450d2fadd064bcc277680d72b5907427d8bf54789a957384d698d54ba2aa9ad77ea65d37a5e42af5b0b10595164f068b2c5640a" },
                { "bs", "a3b53f1cedeb2f30bd4b6e006bc3508b56c89e7abe83e51c0537c4375d418995e80602f33213440d2bbb5eead26f1a6d68961cb83565b67383d6b944bf64c411" },
                { "ca", "b2ed7748160a6a4b401ebf058b59d9da8134fd4a413947fc69be94c5a8ea91da6a76db50ecb1bb8d79d2acd1d211352f257fa38aef9ea233746d5a45f36496a2" },
                { "cak", "f3599d0c4e0c7b4952cdfe776b24f077cf200ae40b639283ae0969c7e59c305b606965866c14210f85bd168a995ef755e7fee931212cae25f2a3c341e0198b17" },
                { "cs", "a2f33510ecb25b3fb1717061a3b5e47382f6bc807223e531fd8761e7bc637d07770dddf1f387e4a2041de96732f6a2bc14e55d94d15f0324a5b9c0eca7958d2f" },
                { "cy", "1b702e49c77f87eeb46ddf0bfa78c98d6346ec1b0170d52603805fb492f793b8fb37228471f2de12dd5a94619013785718af2f298068994c1b7415fb384afad5" },
                { "da", "19411258bb8b7f17c2afc68dab62ef5ef54bdf9423a0998c3b19587c088fabbacca1b3a1bee1cf1ef7d659c16737a79b8112efb79afc596c2b91cd6dabbc368f" },
                { "de", "a2b9ff7ab123f6ba9295434f77d95aba1c2e98ea4533432a9c35f3cbcc191e91cf42480ecebd2d7b8d360b5ac621bf32235d65ca890f770f0f638e147946783c" },
                { "dsb", "7f1ac26b8f4fd70f3107679dc17ee86b46fae54b37ae0f1faaadf74ab8b9ff7735e0a5fc1e655b197dc3e390311bd30d98f10ac1a650a8099ba402c54b463ccd" },
                { "el", "9e13da6d92cefc3edfc075cc3dcac06306117fc1315dfc63572e490f5f9c4ec734d3c91d86d8f73cb10c2d820b35fee9de64a932e4dc8b29ed1c646569dbde7e" },
                { "en-CA", "c8a03576d10dceef4d6a54abccc288a089c66a00fbaaf0aabad230d5a30be4d1f3092982aebd728368d6b871fb8471a486b378b79972c29cf08b6976381b9c8a" },
                { "en-GB", "b6fc9cd336630923834d4777fac9fac0d6a86b7edf93b572782b5ac561a46e097ab389365ffed39c682cf4828a122836b60c74590b94b60034e93e08892e9720" },
                { "en-US", "3e778637fb16688db7a1519973c2fb865e23d1381563ba4bf18549f0e2297ed2ecfe469cf3a9b484588373f54129ed995ed9ff4f122151db74e5705f75c2400e" },
                { "eo", "940d3480a3904e52e5cd52a43a9c3c93912ae8df1809546778d556de715becf5f61bf3fdf1b42d533c20ba53b644c51c6ba282fc922338278b61d7186bcf147a" },
                { "es-AR", "46799882047383c4caff369fc98c49240377ee548bd098fee1fa8dac6304a7efd7ae6b53cbf122459b659d4b658d3cbd5a05639f3f7e10c278288784bf14afee" },
                { "es-CL", "4758a4bbe18509e9d441cd340b08ea1a84f0f0eb79d89dce7186bc4b93dadd746d1f5667c267fd48073512ceb931f8ec6012db4b5989d2d5ecc5081748f2377e" },
                { "es-ES", "e642f29ae515f708a9afedb7ef329b000889d1024562dfa41aca61520ddf6fc96956a00d33206254df2d983eba694c5645b25f40bf96f402c1e4b0c3d1915c8c" },
                { "es-MX", "76f14fd40ff767331aa6cb17926f3be324ddde2d22e7b12fe1cfcd5d25c56e624b79039f57d230a23d0748425c94be4b44b77088949257498d89a4296fd30fb9" },
                { "et", "0a24db57a10141ffa458f33d1a1d4ed6c3e303cac7ab9fa73e197e123db4da067e53fbf9317d790dc2eed2b88d28791818e4776419fbe01fdb0e6f0a675dccd3" },
                { "eu", "97efd3c8829c2454f0ef072a7df76abe2337a45937e0777e637bedb73f6e126729bba23e2e6caecb461da8f4fc41616dc0685e49ad3daa79b69ef1ba8791cc5d" },
                { "fa", "1da0aa1f40d16962a2dfc0f7bc4764240dcedfdc22f81602d9dcbd19fd8abfb36a76232b6633699b426f7e712531d776a2f510b32e29d01973c8da196e1d366f" },
                { "ff", "26975b112382891df64f794818a7ebf8e4f4ba6d35ca5850d6029c46360c0013413daa62826ef45e8fa195a7a423f4db06396bbc84526efdb94833acbe98ec99" },
                { "fi", "79b91e042a9af6d33f013df991583ebab4dcf11b3f6959acd036a1a8fa03e4e055f10121a6bcb399aeee00b5cbd69b77fa9a5f5cb5638d793f03da3b8e13ef16" },
                { "fr", "bb5864c0f6f29b374ee2b842fb3e7a238bc1a8528e360db002840ebfe41647380a90cb6a4ed35db441d0541402b4d14720dee3f0d5a5475bdcf89e57a3ab6afb" },
                { "fur", "30adde0151bcd9b82af05dec5c8b72c78eff3838d68268c55d65066e90c6e1a95da95be2e5e93ee4e30be8d985d7345a7d06210e03b51c0d3d5842d5b65f8346" },
                { "fy-NL", "c7db0897e1a96bf8f2ee208ef6ca04e2b68b99437cd55809f6f1c38c30784eee0e15911b68004793720e674ff60484c1cfb806d63c8bd529e19a65ea5d8214d5" },
                { "ga-IE", "0fbd8e10231629c05ab84f6cb7d59b6495f24291496c2c7725d064240a3b686ecdc1b8c3fe133657a0c515e3d1c3c27c1605c48db68af72ec36c49a61e2838b8" },
                { "gd", "40b8618befc1563cc5e9fc5390e9070672868d4db9c9b0fa1d1f425c258d92ae79dc3feff6ac29287dbab5283acf8ec4a25c9f5d38e5ccd4e8fa4dbe6d4d3139" },
                { "gl", "ea84ce4be6d4ef66336e99576ff6d9984b5adf5a5423236f07eab3777705bf70b6384fdd974b188c971ae00904dac2c35031b198cfd58223cf6795b55f8b2e75" },
                { "gn", "a4327999079efd9ecaa3caa964518875e4c2537408d5f5406b9911a792e373e628a7c251596dc995ceea7bee5c9ac6afb009d316995abdd375d988b5ffbe3027" },
                { "gu-IN", "fceab6f371eaa5612cd9c114a46f904c9cf8ceebc83615d5036c6f214c78de1138063dbf3f03c44e40a47fb983ffc3fc249006ab64d25cb9cca66ac148f20994" },
                { "he", "4b2e9007262b5f999be718de22b26b8114ebddde29263b03deb07c6cba49b2bebb4f1440b25a21c2d034acfeddeb2ecf2ec3eb869652d7759c0c8d5a0fd00107" },
                { "hi-IN", "27362148c3da643773544bef416a2c8e2e5a855fb17090aabb895f4587d829c48f5c8587966f5acfbd8afa2e1d590eeaf8b898386eca5235f0887f3feb8f3c1f" },
                { "hr", "bc548fa1d2e2b8c81080911ee9b913e3988b020e9f34a268908ac7d01279c6da6c6ed70d2febccfb5fcecc8dcedfc74ff5dc1814d2b53bbfcc30ab8c4f09e88a" },
                { "hsb", "31f5ffcb2bd8b00801d5b60a66db4de821c3bbb664bc46c755d6eb80f0c29c31a174edd3df17ee52f811a9b36114cbcb084e72c61fc9974e52cc7e8d21473853" },
                { "hu", "1408cea057a342bac1f7b3c38d55f912a0a8961f1286d8a626061b3cf634a1ca4a17a1247a939d0fa1cc63155a2d55857a0b70e43519cc21f5771955abcaf0e4" },
                { "hy-AM", "4987ab88bdbaff8e2ca94335a10b9f1cecb43e2b60fef677e596dec0b8fa5fbda062e7d7f7dd6b86d933ac6cedcec8778ef6be747e6bba4ab5dfceefcf0ada52" },
                { "ia", "0c0ea0c14a04493adbbb580f9e6c67085c095d079b3b4bb38bf40393519c9ba1f8fb544d10de15aec5f2be4a4365cf6e6ec90b654ff0bad0f3bdea1cb1ba8cb6" },
                { "id", "236885e0692997a3fb139d65190a3c0cf4eaaf15434779f6c5a869e603a19aee3b83709780337053e05182fb8e5fd3b04cd6ed0c9b3defa5518095731492b0b7" },
                { "is", "4bf7c9c823fd46e97b6d2457f907268afb8931400e765554e708138f9e12895a42638ef500b64fd8018beb6e35e485a80de260e07759fdfdeb757d9a913ec4b5" },
                { "it", "55462a282fc1d2dc89894681fa188210cbb8943a4f8d55b97e8b6108b40279b5d5180b86daabe6ef5312654a4e11f13b5484a5968614a046092f1cd6a1df7ac2" },
                { "ja", "8fddfb73cc1e44a6b6f38a53290575c81320768d9d4c906f613b7644d9b7905a3c06bc902ab441064221ac502505f3a5bd4fcd0bdb89de348aa2476c1ccb818e" },
                { "ka", "7d04b142ecd3975d186c557f6b4d18e3cc0d6f01408363b552959b2cf862712fc18a97ed8b42e24daacc002f69e775425932833ae28eee3b6bbcfa54618dd8d8" },
                { "kab", "4dc7200f5eae7027d615bfaad7b94783bf955d51f4727d0702e17d3c0276797297dc79d3c2ce21b0f03494148730ad8db308e50a53545555216173c7709aa444" },
                { "kk", "ce155f57e6b0ffc8bf465b6e806924b798f2a995d8f6062a65d89f1c11d9d4eb7b43efeedefd09798c0b974fcbc595b97b98389c9c986e1ab381fa1f4e8b484b" },
                { "km", "e517aa9b2e0173a2fb26b33c7085097c3286ab1371ebd3de7290817adfd9224ee38fa22559f094375ebb24810343c814506997e4317cfc8e3cd5d9135de9e40b" },
                { "kn", "257e9d31d99ebc167134be5e57e3799782e39622c864756a60cb83eff03d6cd37c48004a292d8b800961032f5056b375c9a8aca1cd8c291ba0ce8f225d7d9fd1" },
                { "ko", "f483c89307abb4a0cf5be1311ef14314106484fa1e5a715f24acffeda22e20d62d0eb3f69a11ec47f93cf3b3376ceb6de4d2bae324ddeb5deea3ca742c5c6dfe" },
                { "lij", "6fa8e72faf669248fb9baffb9654c1fe0ea5f4f989c465cdccf073b385ee6096b92681e19c3d813b53c934f36692751eb80a35270b8ab78caa1fb3c64e9e9ddc" },
                { "lt", "0b792a5221bb19d77cd3e85f5470bc4a479e1675f1347894575e80f09988e62722f40f6d82fac4a195c30cfd7407af2ed39c58d7c242ae0c372167e96bf8d5b8" },
                { "lv", "ba7e46453999d4aee09f5018ce123642a5f3f20547efcb4cf40a9547767334f1756f4608081b6d628c1e9436d96249cef0ac04e77d73ec9c9934177553bb3801" },
                { "mk", "13f8c0fd4c138758991a104a84d08ac44681385d96f6bccaa486af99c48739640f958a6ecba4ef13c5b80fae1bd05005c9e2f936db4bf84b01f0e0c8da546ffb" },
                { "mr", "1212da9b0c880a31eb7c56aebb5e85f18bd93a1c25ce226ea624eda5e7610033e9a8e252b97db07831680120a629975005174e2e942ad8b48430013614de6fb5" },
                { "ms", "cf18fe0346fefd4aa150c5ca16303f346b0678e543c2f3866ca35f6d11906b7c4aed3c903ae064e4060c55333dcc939e2a58f587961b7674111805361f1c82b5" },
                { "my", "718b60e8e50d48b3f6cbd9d53870d6dd9d4149e69b02a9ea16fbd09602f7429d98243b12507b02d330834401194db5b0cd14b7a3de407593afb2daecae2254cc" },
                { "nb-NO", "1a5a14d88131b7cbeb5dc1fd5cf2ce695c96e7985a1ce691151b9ded83ac6582927794d4a6c7696ebf4145b6eb79e0f76aca10679e5961d0f8981615495f0f68" },
                { "ne-NP", "ae83a68318c71fe09cf103f459cf119d5f9eee22a3885bdc6d3b05cb274e6895b47d77e7779d68ae38e03dfa010e91fc5fab998eebeed3089c7f3ad09e752735" },
                { "nl", "b9f7e6338fbc6eb1fa1a5056eb8c3d3673a36a0ada9b484176ac4dcbb8b84da7f8f45a4113815aeaa005f7bab9fa70afec77a78c84407ec106d35ba1f56f2edd" },
                { "nn-NO", "2c3b555f3e122892ed1a8f26a3226f55489f136fdbb01a4709f3c5aa711c263b60cc2d0dd524b6e8ebd651f5aa88232349c5d16e0cb56753c6ce2776629bdd04" },
                { "oc", "747af5ae170a81655ff89224611c97b2bb632c5dbe97c9a37b79d9f733900275bde70f735dc84eb9a415dc391ee921bb7c1629b03d4f173e46aa0af4491607aa" },
                { "pa-IN", "e0e74a980cf2d2e1f8b3957e670f36463fcf8ffa8fcc749d066799fdfa3b43697c6f7c683b3dc4502eeace0fbe700a5a4c4cb76e57c1601b742ea9c47e5d6f1f" },
                { "pl", "6eca5c8f3bc2bcd35969de92e0857e7de7082f0a1a523958aea087b782801807a9d24ea76c726576a4b322aa1ff0721f7ef7e376ebd702a8fdc61e4231630507" },
                { "pt-BR", "2e266dc51861c025a28fe4c86c3112503b917c626e88834f8b29b991c731f6c789d2be3413f2ad2ce280a6690c2ba0ae303771ab93f0f8cf4ac5c62292c45650" },
                { "pt-PT", "7c255bb9761f3e9ab02de1e770c9be8990ab593be6a2ac89b89c353347922476c3206f99b37b03cb322670ac6dd5541535fa3742aaa218ec2cf7aa4ed0eaa92d" },
                { "rm", "cc82fdaf8a158700880f91c3ce2b2eace7fd24d698df63448d9d3e09fd41c63eb811cc0791fe2ef6be86a3e1071c0f3520f8d5a6dab9d08fe2771fb302a52c07" },
                { "ro", "e5ce0550a2cffd45683a859901db5dadb99d6237b4ffb4277a673bc77e00cbc3992d30a61784365b8a0b6c41be6a02792744742223cf2c4a9a636be60eb668a0" },
                { "ru", "c1f97a97f24bfdb0ca5486bfb44c278c35c9332fed60c2bd6360ed66fa83c7064acd08ff7771e6486d72e7fc8a499fcdcadc5a44854b3b8fab3d755ca68d7cc4" },
                { "sc", "fbf199140fd5ba6a31c51dfd811a4988afd2dd517649b13d689babedef2637a46382be0bee22ebe0a8b5e09e70efad5eb8638b6f8267492890d7c3897ae65225" },
                { "sco", "ce82dd08d3b6f338f54a80cc3adf87035a5e4175ba609985faa6ab76f60d36579c624c92ea301061646f9d8841fdb25e73191686c490a71ec0010abbb8937a07" },
                { "si", "8a339192ae0b69e34a67474aaa85e507ce18e1b3b4dc5c5a7620c0e7a99fe78c47001d2193ddfcaf9a6b6d63ebe91f71b973fd9ef5c54281719cfc7b749334db" },
                { "sk", "1c06faaceb7a47a4caf55b2598e948e1212a853cb1991dad93deb45b54cdab0109521ff5e501ef56e56525f3f8c233c109326af8728680e48753117dfe85e19d" },
                { "sl", "b0532522a861f25be96679f5ebd3d7f7c2720655ac055b3d70f76703c4830af91db7f281b78c71560aeda5c780d189033b4ca4a4c663e727436156f00fbbf5c9" },
                { "son", "6a713d6f04d5f18bf78064fc3dd54ce4afa9cac87990a29773baa2e8c56ce828a0ffb624693a80e270da1eabd6eca05d6b30a7d3ce3f1b553636ac450d3752dd" },
                { "sq", "c0ca2c7ebc24a1ea486a292e0f248dbd09517ab9049619f80750fdb53f8f0a27cf102f3e589d96a3184c9213bb2c7af35721b3b223c0ddf309271702c52a16ed" },
                { "sr", "9c57d10bbd08fd69ab5b306a305adaebc488e1b5abf3909188fcf64070fb173ee1e110902514eb3ae5365f83822b1e297c7a6616fcfcfeafb64a95007b502fad" },
                { "sv-SE", "5d49db4c02979867fe36ab19f41b87f6dfb1d1be8b6ec72084a6d6bd93c697ffd36f9b0750c5d874e2f21a36064178d1f74888c530bd6143c88cdff2a218cc56" },
                { "szl", "51efcc0c9d28693e326f7197e5cfb387bf5ca83fcc7275840738328f2e4d77c8e99461b19054e8170e8d83de1f27154a89843608b9a4cd8667a243a5649430df" },
                { "ta", "9ca1d09827a6a7c4a7b2f778dee05bc37e112eeeebfbb218cca144ff12680b634f77420d80984fb291fce228b58e96370194ddb7c47cf6c139e95a035b35672c" },
                { "te", "37be9c81ab1f04d86a8043648998a1b09bdd77e84235bf2e2ad6828e7b2320d678d15a00047b8c235c2930d7cf9c64590fd81d92b4653319705f4d8ff6819cab" },
                { "tg", "d580170a4a82da02afc84e25d4d16129e52fe56e1bbe11780d23ca32add34eef8ddd2a47cd87efb981cabdb433c736813feca3e7b4dcf883efea430b1bea78e4" },
                { "th", "f340ba298128f4a87d91d6484580aa52951329973c1b898b27d4f10f2f576f382a43ed38c21d455b92fa9f3b15d4f19082c08f0cd5375a389bf37dbc5837e5a4" },
                { "tl", "9f6087e77af3de6386e16505d4f41720730b6ace217669ec94ec05cdff57903d206ec0f0f3eca343691a9f6f3a6cc9b2f1b95cc6e2263856863fc2e5d8bb7b6d" },
                { "tr", "29b6324240100c836652805345405b2c77d2b077281b8a65d8a5ef32f8d0457185d2ece05e81c76aa0a72b62a68f1c8dba875ad2feb805f77cf8038c706c80c7" },
                { "trs", "16285c3d00267e16b06f339ad01f52079afca939db2fd84db96a9ee03d69b858c3fa82614fd9933afb5d1adb0564c43b6056f8906d469eae68c2092548a7011d" },
                { "uk", "5204a36022b5e8841eb3fb87eb52de24d1e2bff87323bd33906d3340b2ca327280e2dd67150324ae88437c71327e03d8adb6caaa6c41c597cda1a0d552a09840" },
                { "ur", "abea4d7af10739b03de15a128fa65f219c43c1748ff8b01757ab6f4fa7c6340eb0cb7a2a74012d0a8595655a2e4c19cb28de008213138b00dd6c605bd8ac28d1" },
                { "uz", "baebbcdddb149fd48cfbb7b287f254713c01dac4c04fc8a5b5f7f59220bfbaf161f8c63d70da4d68df5fde352c5889d6dff5a11aa8b5e80e1268f84adf8d8f6d" },
                { "vi", "60e661c4eb131f1a79d31bc3b0be9fabd8711dc70183fad9f6510d209abeaf479c01f11baff63faa80bed5511d920b618abe2b8dd42f43dbf8e246cf382e1d1a" },
                { "xh", "ef9f0ceb05b3ed3fab43f81461728709db975a3c0d1c8eb839f9aeed0322ac044d9c0ee64b11b296b1b44f72c9e758c5cd465fdc66169fc18f59b4c67bd15c3a" },
                { "zh-CN", "45af29ad4c971cf80ff0b0c9df7ea213d810d817fe52ef2bdc6187c6c53f8fa48aed7b9243c50d09fd01a9ed12ad92f406a11bc767179d1c23ba3bd26c2a817f" },
                { "zh-TW", "e72846ab596cb864117bd595f10863c05a8d1692847c90f78f6320f3283567c6bea4837566a60190216504b4c043ce38fbe5d537ef13758befef2ef2fcaa6dc0" }
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
                    // look for lines with language code and version for 32 bit
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
                    // look for line with the correct language code and version for 64 bit
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

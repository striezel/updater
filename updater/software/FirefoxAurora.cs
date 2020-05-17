/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020  Dirk Stolle

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
        private static NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxAurora).FullName);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "77.0b6";

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
            //Do not set checksum explicitly, because aurora releases change too often.
            // Instead we try to get them on demand, when needed.
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
            // https://ftp.mozilla.org/pub/devedition/releases/77.0b6/SHA512SUMS
            var result = new Dictionary<string, string>();

            result.Add("ach", "73850f361c4b829107aba5f3b11663dc83e2fa743176f57dcea35aa31132216227558742b9f55b83331f1ed60d877f4946febca39991bd20b21d658bd853c3ad");
            result.Add("af", "39fd87b24429858d06812769a0f7258d5e1d33fb5c4655e4515ee86024251778c504e1ff77ca9fcdd602d2fd0169a30cab1fdeab2e0f56c2e40cf6c73adb2b0b");
            result.Add("an", "52041f2db24f49c4307bf504759a0ba894cfc260d171f1f3229d774dfbb84d4eb988a5a4d3965b1e639e7602b7b953806a0d652f926144781b653b3459a7a55e");
            result.Add("ar", "b2b79c3064ff115477eb3b5baea7f9d5812f51e1a69bb9477552459f6c9426c249fa343ea027d48d51953b9994088d9da1882cd93d8fc74d2aaa54f732c96551");
            result.Add("ast", "1a26a7405dbe456f8fe92681f52c2caba234a4861099f72982cac15a3a5eb507890d57664999969386d204a3d189cc4d17d4390755fd74bb78210afc8595a8cf");
            result.Add("az", "d11dd5060274c0c162dfbbb3105a54aec59ce13a5ab61c4ea6c578addcc843e801ef499a3f30c05df7c8bab8f7bdc5dfd498871caeaf8b92b8c3ed46aba21422");
            result.Add("be", "4e70b5212ea5297188c51c24a79ac7beb6ce998d0b913af7581d9ef6bf2c3e31018d4df84989569f03670c31a73fe658afb13224775a03833c9525dde00bab9f");
            result.Add("bg", "3f5bfed4b30c2c4e8808a3ab79a7680dcf7a3be9181f0e808d8ce088134e976ad3db1d494d403984c4559b3357af173e7b28977eea548f34de081310fb5fc0ec");
            result.Add("bn", "f6a0e1625956baefc0c317ddae1eca208e73e00d73b125f63b9af0043e80e6a7f8400a868894e9676ac9698513e079b8485ce3104b8bd482ac5e53d3c4678500");
            result.Add("br", "1bbb7653321d21226a6420b53c8447d958b3eb951b1b3f41d7485845a9b8cd995dc8f553ac2d968efb6b5b95a21e4d39faa6cea178918a73cdb2b48b6958a060");
            result.Add("bs", "79796db0956c3af0512a0cdd2312b27edd09be0e87fd2df13e9601c46324281a690c95e30a5e5ab2455a9c48191e47742413233d1293b8fc25529736011a653e");
            result.Add("ca", "3365853d44306e77d5fa9223513fecfea42749ed43d1037f24ee2273ab661327b1c2c9be0d038a927b385fadf58eaf5a416c5c4519bdaf5a89560791bc3d86bf");
            result.Add("cak", "94be4505b84bd4c08a78b65a2a63a43b033618830285979f26f99c169e41bcc748a7fe06925d82453f636c0d436f18d5b136d86658ab0d807d0e1bff3cf4fe14");
            result.Add("cs", "a384ba016c1c7c700ccb4a9586a91325a1bb617f363cfba6db3b07eb85d5696425e44b49a591194b177b140af9c5610fb2f1254b8580a015903f08ee16ff95f1");
            result.Add("cy", "373ad7a9b8d4511a430b1e4daf63fcb943d75c3746d9f891254a617cc30fd05986ab8c2c9faa33461a3b6a99512cf1c4b60df9f1a77b87fdc7353d875db9550e");
            result.Add("da", "2c5377cd67bc13776307d3930cc9913bae1959127449b903739b32e8bc88ccf09c790bd273ede7df748bf85252d53884b39dd4c9533c99a8f2614f62d903558c");
            result.Add("de", "a4a5a70411d881f3b0dac78ce444c0714d9efdcfc3d3a235730123a7c4e8d9e36453fa9f5e5e82b825d51466fd690aa99e269137ed7654825646be610e233bb2");
            result.Add("dsb", "5af225bb94a94e8ff0ea97d40ae98504216209faf1a28ff2a3c1dc05d5a7e6b012a883645a4329cd3d6b9a090057d059c39bfa4fe4428f2f3a61a77fdf308621");
            result.Add("el", "8a97f4f8714b79ee4da24d2ca4420149a79ed280ad2f332df916a85bb2566f7568a3797eb98e2c308a91d77ce9e50cfab67f2f52e56826b0d0f8483a1f909559");
            result.Add("en-CA", "fa9d375dd9f3ed49ac382bd151916cf0a7727e44347c944992c449f252530b997817a55dfeaa4e7e8a4ba53e9bc8cc76a78433e0c2956c0bf264adcd24c5ea08");
            result.Add("en-GB", "4ccbd268691f43683f1cc77b035eb43b0f25fb69ba059578b240d10f1d605bec6daa39680cbc7945e20d08cd9d0fd3fe43719bdd6869d7c67f2a33f005b459ef");
            result.Add("en-US", "7a5faa47b0f396207aed0ba77d32ba30e2ac18dd468a3fc0cf2744590974f78f1c2fb4397e5a605a53f7ff25d9494ef00ef34de64ad4b126b5c584bf7b28f2a8");
            result.Add("eo", "b1da23f6184ebc89e3a2eb9763f64f7c63022b7a23f648f830878fd4f94662599309d12d2fd6c6886aca88ebb5d6097d26a81e3b8c7d240c9a451a96101dea5c");
            result.Add("es-AR", "1fc8b6a3bcc22ead68a1bcccd16589bbed5d92f8444ca0c834c2e7fff280f3d39f523b4f8124a2c210d05e1f850cff255252dab020004d414edd826320bf2f58");
            result.Add("es-CL", "565b8303422a340e7fe9f865594a1fb96c6434ccad7415a7566bba2f9e6c36d8ec933325524f9ef0ebe232181ec763f1d5f5cdc13d76133300804ad81b175ad1");
            result.Add("es-ES", "b95a99c978b32bb1ef51dc45984c7cc773cf610f680a57bff081220a835dc9085d4a0f7d6824ad2b5945c1d46cbb0fe2ad334841870faddad67ecfc6b823ff27");
            result.Add("es-MX", "da963004040056c52a317933bc63ae2b4de2f6c1785b402b7e2043d68389e24ec308fc321ff896a54a25dc4ec4d0dafa7c2dfe7da0935027092e37c3a88ec69a");
            result.Add("et", "7842e6813ea07c780bead88b1b2212bccfc34972463b86b70ffe68e68689ecee3e561685a86034ffd799349cf16cee8e8efc8d97cb529817df8ffce8b88157be");
            result.Add("eu", "c3c97b3ab650147a1858f8ca21bbb62f59f6c13363d169bc0354d87df806c1e2a0a91c38c30e49224367af4b2ad90e13af1c0a37a7835c94f4959a9d755f0ad1");
            result.Add("fa", "eb2bc2fe56026247a195187384b65ab13c91aff3c612e4d3c9cf1f780d0017bd4690dae9a14fa44d915d275421dfdb718106d4b9b82bda5a59d417297f77fa10");
            result.Add("ff", "36c797f9a2dd56bc2bef89906fee7173d2e2b8966a160381782b1a752cb149278252c1f4764f554a67fa1968b02f9fa5f1a7bdd47bdb5bdce76d548b43888516");
            result.Add("fi", "f46ffd182530a95a13d0a7af444eb27f6e0f9ff323dc0fbeafde1c3f2aa083d26fc17db9b5709398219c21b643728aec58eff0c9a0ecb53cfe1ead8e9ad16051");
            result.Add("fr", "57f057540edda4fdedbcf73ec6117b5838490f9875f8f112a5f44f0973620612933d52ca4b0b87da12827b3451417aff6f0d8bd397b1d29680c11abf234968a1");
            result.Add("fy-NL", "4ed0c5c1c4866a9efb6f0c93b4778c255b94a9b7f99dd1367a105ba60b0716bd8141b2988a00ac21290df5ce303f2b3ce656403e1ee8a482207e979e0e3cd1b7");
            result.Add("ga-IE", "c18ac9b87c34aae1c43e7550ae0273a784249c3202cc686e936dc780ebcc5cbe4077927d9ebbb0e7fb06d44c94d0388dcfff14bb54d6649e2cc57371d74761d5");
            result.Add("gd", "ad6b23761915334f74674d3e5f5df6e6a1bb5c8f3a90b8ac9cc6cf486c430989494cd083dd1be2efab0a2288d5ce98a9c2591c1d1ddb7bf0fedacf5e17115ead");
            result.Add("gl", "bb6855e58da0dddce80d21d76555eedc2c39e1f28b393c59a20cab6e237d6f34d49e57d28a2acc8652c0a5beb19f7e980d4ba58f9b5e71b3465201d8cf08f36e");
            result.Add("gn", "23d265843cebd2bc15850ffefe7eae178cecd1d75a0a955641a752e7c4dc359bb444325afdfc75cfb16bf48defb65cdb0817f5112cedd97cbe403ccdea3f1218");
            result.Add("gu-IN", "e647dccf0a7c5271abdd23ba4ab7df3f63690cfe463bff362daba78e5cb354fa4cf06d87739fc351d4fd82f7858a21b387e00165ab748e41c2fe56037cebc89b");
            result.Add("he", "67ed93f394f22d81a533ec46b7a7f11d9258b2e120cb8a1fb087d2a7ab5c961fc5791bc240ef38001404bacae2d6bf1f8c9a803f28a3103b84b5079a0258dfe5");
            result.Add("hi-IN", "523c4f06b4f9dad46e4e5f6691126ffc06c4e5cf893e9324af2c83b8e288d624ba7a48befb793e25f313d391e1e4f95af23eade6f6e9e534353a6f0161810962");
            result.Add("hr", "8765ba250e8303ece2f67d64f2c9068f7f009e04660945f287776d6bc6158e3ee10c25843719239401af08c14743e01e3707c18905e7f51ab640b4d50e3356f7");
            result.Add("hsb", "ac72fcecc763639d8b524ca76e6912ddeccc52819d09430253e7f3be680b67539ac468cc226f7fba228b7620ca90b753d5b678a2027e6b4be89bfcddc320c310");
            result.Add("hu", "051c9d8b3b87e7be2c562af0e5c1ae6a48f048d29f03686ec8590c5f93610d3d00871d6754bd24d171de082f6dd9875090f7394a172e875e6b8f76e6a46c2668");
            result.Add("hy-AM", "ce02895bd7f0d0d9a1b3088e27c1d12ed091159a649252a9386eaab4b25c8126a579bc21084ad2ee230391c90c330cc4b7946748e0a876e2285f4bace67fea24");
            result.Add("ia", "8cfca4999627eda5bc8b0a8dd9572303527bf7507fdc8ca35f7660ad99edf2944a92dc53c1efabce24e37c9dd391c3bbe02acce909bdac8fa55c87457ceffeb9");
            result.Add("id", "085023cea5edd18b95e42704381f061d205ae74119064ad52b2607d9e04d3bbdac0de991b7141da1c304a3b902317224cc2fa812b2ec85cae5cec350809278aa");
            result.Add("is", "c900f124ded311d24d64f312b0b2f7ddc0c86103c9db62aacd58094418e311551bc811ca66fa446c1e9ccb3f3253d7f913eeca77c92fb037cb134974f58cca1c");
            result.Add("it", "2dbcac1a89fa8a415e5ab662b421bfc77b59689f4165fb4767d7a995ccc5349f26cdb448d3f2db7adc252cbc21bc556c6c8e15f134f6b0d0ac3f6934ae956699");
            result.Add("ja", "ed643e63876f10fb2a67210c6a6c71846b7a5453beaa49d4ff1b95f4958423262a73f5c2d9f956f25bf372fc7a9733b105ba1695823d9b90a1d41330be845c94");
            result.Add("ka", "24cb79912ff9e33ad32a5fa39f4f7ff2c3bbccbb13cba7a44fda3f82878da9e0fc4d8e55a915b835b573e902bd3dc4aa1af2365f9925b8b017dfb071b1a44cda");
            result.Add("kab", "d8774c5b5ede91b26d45918ab3161258ff4139edfd03b98a7d57c5005dbca685f51f0da22ab0d6d7e81214ed610ade1860345ce535904caf11ed0e4e9e2c9b2f");
            result.Add("kk", "111a3ec1d07410c0916c53db6218cc84361c6e7de44e79c16db79083fe71288e075ccf3c5dfc6459c096a433c3c5734fc11e8e3bffb3384d8b18d0bf933d48bd");
            result.Add("km", "703a6fc20bf57fd36291c629784004d39b892871ad96f6c394b98a340b1159e0d662b13f52f85849d4b4a13f2c076929cdc6980bc2d783fa83cfa8fdbb5d66fb");
            result.Add("kn", "f5ff702d1f22969f0394f76cd920abd14708440cabcb3d443f19592a06235f42b7e0689b23f620dd078a1c584e5049ceb0212a73b2816571bb37d13584ff969c");
            result.Add("ko", "72e88ece074b77e7e233ad5d1ded4c89440c311f907e17faa009ab9b8ddbfb26c4e0d21ed2c159411f1556ae5ebed470e90956ebcf71ec0f886208181c8d8865");
            result.Add("lij", "ecf22c5c66255fe3ddb44175657c89a27471a55d061d10cdbad6bb8af98a3e03f187a8ae6972ece176584eff4b7182c163ef68cc5757c1a0b6291d46f7dc498a");
            result.Add("lt", "49d7405dc2793ec92a9c1949adbd4b614340a894268feb0b3baadf28e47a5944104a0392085f57a4a4e7297b710b73562cbf34c98c5095cf8bf36af1651ead93");
            result.Add("lv", "b5e1d3b1783b39638bbc0078ae49f16d36f90066659f832debe2dba8238344d915c0119be0976062d0fe8142f1e7fb8f5a06a14a64b3fee9bbb8b39cbaa8a757");
            result.Add("mk", "65f44c9a1511bf1b268adbc7ed8e6b1d4e6e0ab58da07f269fc3c2d380ec84024040ad4aa11107df5cce20469091cdd3866e4666cb8d643b4ddeff49ff977b5f");
            result.Add("mr", "c7e5437b0bf2c21e97210cf80eea355bb9ac228c8bc5b1ab7e59342b527f8c7d4585119c702a95a8b115fc5424d96de88f3cf0f1012032d83f3f913ee5abcd2c");
            result.Add("ms", "76b929812026ec5f7f323b99ec487abc4892bad6ae068ce26c1616b8e3a2b867650fa90917ba9575bd0e69d99a83e8d193cf18ffb9a8f635f228fc23e0236467");
            result.Add("my", "09b1648347054d762a48f6d2a5e7c38f0ea32b2c3026d9e760e10097a6dbc6b1d831b7cd43cab5e91165e9ac70c31d391853d61471f927680276ed893e00009f");
            result.Add("nb-NO", "d520bded1c82e94b4f1359804d269c3e9f70cc9b1cb18ffa4e295cfb9f0ad821b71990197a0a115877f7f1ea8a1649445ab171df0698582e0d7906ad1e5a6172");
            result.Add("ne-NP", "62f7970d5e5c94411c27598b90be90473b6be0b6563bf9cce26dd7f6ec28a2f62f1cc17032277945129855b65e5a4ebcf2372185eb03f7bf287b092f3ab14c50");
            result.Add("nl", "b48644a12911878467cf1638686f18e7c1fa20736ef3d3f163dd7c4a7de41f61aadd4c1749eee425a3f7aa19c686a6485cf4a076cda1f70e54443c541a4c4546");
            result.Add("nn-NO", "1bae7ed1a5b38a5e9b9276626d841a933969a7332d646757b590036fcb87f77ef46b7664af50e6fed4764543b388d8dea5abcf73704013ac9177bfa2dbf06c9e");
            result.Add("oc", "10430cfb3a6c965576adc1989177c7b590cc919ff1dad18632e1ef45175723ef7342cfa0a43c287f6c3cf08e883a7ac16d0ed931d7a78488c8a38b31a5493044");
            result.Add("pa-IN", "ef58151abbd298dd88855854fdc5e399522acd98bb5d11af2ed282802935c6791755325866d45e512fa3e6a3e83d8ad95432b87f73d82b53bf8e88596fdffddc");
            result.Add("pl", "bc421fee9b80b948ccbb110edefbc397c9bf25d146e340dbc8a9eb18088e9abd4e246e0c5ada4ee6cfc5c112f6a7ebc5e33a6484610ed58a8791eef0c2203e46");
            result.Add("pt-BR", "5b8fa6495945a34a384fd00db2a6e3cf875d61b93a694a5f211f8cce2ba1f9282f9fd13cd22b450b65bf2187965e5bc951887e26e04898759d07c200c3ee4e15");
            result.Add("pt-PT", "5012c1fb04f09ae23317329a4bde46a89cfe868ff0a03422990fae7e3f0c8a336e7ec49df9c62a32242f8ea574e3cc701a763197dd0dff750d7ae39f25be6088");
            result.Add("rm", "fcbd61a5d40b3d26702355158d616992a701a633fc150045c0b69efe936e85ebf08e2296a15182016c48ca647959a26e5db63f09b93063730458f841f75bf58f");
            result.Add("ro", "b7124d0e061075fc48f3bdc291dfdcbaf25a13efef39f13ec878fd4023be6927dcadd050713e9a984c66e93cc38e68aea17e918d8eea5d1a1f1cbf39f919c7da");
            result.Add("ru", "73e9c3ca53ca5957648aebc69cce8e8931b2c254f95a6b72e48707e010dd0f8e362e199560d1c27babfd3d2022f361674be46eb493f3b2d951e1b2029d57182a");
            result.Add("si", "1f662457025a814f814248059aba6b09100080d7a79e1dc4eeea297dcf308734fe3aaf21b3bf96e3457c49643bf4cda27f41f85147523c9ee581427f307ac736");
            result.Add("sk", "37ee14068f33e594c56745992a2b800ea20a6c3df5a2a6c41ad667d7bd40662bbaa9a6deafe910b4315d6404e3f4ee5507c8171a21f698a74a8d26a29381fd88");
            result.Add("sl", "26347b3cd5095aa7b9b09be86c2944329d13fc6536cd865800ae9908c5a24f4b177a6fcd55d805c4ac45e70fa6accb1d8dc7683df45b93ec0ae7754b2195662d");
            result.Add("son", "e9cd42cf3779789445b9885791ecf526b52f3fc58bad1930366a957044d9193ff2e9f054d8e6cf232d7d32331be002fe7b5788ef750425bfc2ad13b3a498e1dc");
            result.Add("sq", "b92e486c4210e57d8314d2bf19697b035e20a8c5b0333637698f3a442301e9df33c6e4f2216294a8ae0c67419cb860a297302dd5c29c72d09e490983b41ed69f");
            result.Add("sr", "8a618b577eaaaea80cf698c2b351075f74fd5fe7df07419903cabdbb4f6ca368007d6ac902716787b7c537251f956a69ca7786572a5cc3fc2c826acc32fd7824");
            result.Add("sv-SE", "13b37ea2d6d57890ce463e5265df02e9bbdf0c78c15b97f8ff2b6eb441cb9ffa65739c4fc243ca35340672caa7fca54678fd6b3f76c4bebdc057b0f9f996b4a1");
            result.Add("ta", "986f2e78d5fa065a13a779ee2627c400774c09d24114d52c0efa6dcecee3542c7f122080307f7e6c394b774468bd36d8708e37416f9709960bcccfea62c4f321");
            result.Add("te", "025370a27523b3d46629a5ea57af1cdf6b3982f7cb67c0cc6834214a983cb61284a30b53f0e88a310b3d687d2d329365b262350836f3d222e4b44bf935933dbc");
            result.Add("th", "85bd5de2c1d30460963487edb28ee4fbaa4499f982622fefba8ce72b567fac8c7a8f9bdde6bee38fab9117b15bf606fd44700787e7e52fa6cecda33c88a8df49");
            result.Add("tl", "3eb54f053f068837538ecceab499ec1c44aac342d258f04e358a2552e99008605f5c569a80b885900397e5bf4b3b36a3c32c505383f40a3b8f8e663f5c49553d");
            result.Add("tr", "438214d154b9346326ad549f658e31c4e51a6361cd2fc6691675fbf3277b134d4ca31244a0a2ff23baa824255c24ea982adc37e2fb59f35a61f521d933366de2");
            result.Add("trs", "195ff19b69923a5756763013189a53109e1dd203c8042109fa0446bed23927591521f368c62c2df917b5398ad818cefb38f537ab575bf4c4d556c802e9ddc26b");
            result.Add("uk", "ec147c7f387cebf2640aa3da557455ebbd52f1a4cbc6834eda55cd7e65697f6a1ece7c0eb7405909bc847ff764d4642d97996ee254cb1d8a547e93062f705219");
            result.Add("ur", "e6b21d4d6b79a579096e1c43c386ca9cd10b8ff0723239688f5bd0a56732cf1885a2a006dfcbb8c125d97a24203b96b6b742e95c3b3427415b41a9cfbbd59e39");
            result.Add("uz", "5908520f42f4939c9ef6c9e8c9633c0a106f8a032efe50f2567b137e0923f03c62daa42fd782cc65216c57fa306666bee76e77c0c476d7856d328cadec5fbda6");
            result.Add("vi", "9cccce5117e28f365236fd310cbe53e7f6b96151db4b9cd68e604daf8272e3cd8f020a47371e2ad4fd8fca7643082c79154c85e266ec16e4cf0fab6e9b4443bc");
            result.Add("xh", "98b58ab6b6e014cc08dac28bcb441ba278afce0158aa498a0c362bd0a2eb2b566c3df7321915c64e9199ee7d698fabda90dc262913fa78398c2df6bed5358705");
            result.Add("zh-CN", "5624ccf84c188b6c632cf36447acd496dac181b3ce292ba999254b10805d3f3bf80fb70c39ff1a889500683c5a54d2b9cf139b9174cc8b6cc432f60c679bdd22");
            result.Add("zh-TW", "8dfe9b5c74da4ccc7b87621d42f371e82fe80297b54cd233fc52f13c2b8d306d9188023873dbc0544cdaee64c1155955bfb08b085ae9275811a40496da2111af");

            return result;
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/77.0b6/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ach", "e9ad227522093b76e04d453411210018f9ea031de0df163954c5ab6492ecfca837e6500305510084e77f5d115596fffd8e52ed2c8023fe8c9ae0bf60b2931cb6");
            result.Add("af", "85fe1fad2ea460c026fbeb6d36fc2970f6ff500dff4f87863e693d7368f835ce1f55b8896b04ecd78199a070a983874dc1d0942f9bb6094eea617959ec242b1a");
            result.Add("an", "8644759795d6d2d131e78d61a87f0fcd6d5d336c9750060afbe3db908025f2ef242b835bce3854a1d816bcd0c0d628db1bef8038660eb36ffe0dce224f115ef5");
            result.Add("ar", "3087c076e1d9fec5730593485c1d9139a6b6b7bccc5d956ab0b1843792ae1ec53ad67a6f46756f36a43ba39320d6b5d15d643fa8edc666199176820d3a1ca35f");
            result.Add("ast", "3c6a4b3250afc4c2d70174d0725cc7d961cffd9980e78d896abc2e3598b68f2a1ee9590b00140eb075edde5d978dcc01228e76863b3af89fad10a6bf71e77a40");
            result.Add("az", "dca52bcaaa1b34734d5493e17a5f96ced296c422f3158b8222ff84575c869ae75037359ee546579a9cf580636f4147d6578221b409548d421c6ccb6b37ddd252");
            result.Add("be", "1bb23d9c89cec23a1e01d2b392ab8417f55ed62784d2208dcc2647ecea9982ae4039e0dfcf45ee420f23ab9ae2271caa0db5d90a0a28994f835acbf3cdf2f88f");
            result.Add("bg", "19bb92c1641df5858a2727283b5ccb18ac9d0eca7bd7918c5576727130797a79fe1707fb4005a99111aad31ef02ef22296ffb88ef71c878456b4e0e013b07c65");
            result.Add("bn", "31f06b91dd9c621d7ff10a35ed5ce63210e837945b555b7d8135169d1fd87cb5f379e5f73ca68225411db4a62a5f3c73b87e17863c4b2ee403b602e673986166");
            result.Add("br", "99dfd21e4d609c2f813ae9b175e805b37ec7bc80e394ed201903f38b597d50d53594fb4e033b22ce129d2bba49a3aca5cbbb3c1944b621ff332ddab64014eea5");
            result.Add("bs", "8a5ed4224c2b5f890749622fe0b1aeccf0073bc18c4f71734dfbbda8c199908905f43560b12867d2bcdbebdff194048078f133f8dd97ca2dada7f9cfdaf168db");
            result.Add("ca", "f271ffc6dbcc2eef5ab8f4f8ef562931f7c2d1e7583e178da1781a599f78e4cff34dfe3961bd66e235de25400bc82f59dfd0cb1a917740019930fb571674a7f9");
            result.Add("cak", "e6495e67c8575efdd548023da77d658652f414d0e1f39dc66017675accaf8c7925ed7e88a766a182d4e7ee8642da49d49b2e2fc9e92a25ec9081d0d474b93072");
            result.Add("cs", "e32d665772e492b62abfbf2eacd4399d88ec0a83b7f4cfac75b702c48fadaaa988e8cf5ee31913c64b47e7539697c2142d0922da36c056acff64b1408dc9ce74");
            result.Add("cy", "9eee3a515674cf20ee055549bab4ba02f6baebbfeed31299709c5e551cc9b7497c84a989288800fcbc313731d4e676e5f28928c0d89554cab18415bfd4d09c1f");
            result.Add("da", "8661bd20ef28341fc23d865a957828472b19655e4d76523ce21e963ac45f688982ccf0390297129ab95550273abdf7f565b4bc8d9470947f1914b29b6c2ddb92");
            result.Add("de", "634b108916cc880a15bb29ae0fd65319d18c9dd234a6076a3544c7bca34b67108f7c380269f51d66631b14941b16bd422df32faf31982d99ff4bebf91e59d28e");
            result.Add("dsb", "47708de0db1ab6df86726a94df78e9e8f41a2f526f0846088999566b218d40e0c627649fa908499c077ab8d042d87ffc070cedbfd0c918284bbb9c03d4f1aceb");
            result.Add("el", "b391328838d2e812a4eb7e3689c7562c062889f89d4811df135c4228a05608006d47274db4186e42cd807c6c109c0075f75d4451e3ad3558a06ca766769d797a");
            result.Add("en-CA", "ba303c96d036153bf5a30bc5b3870e299aaa168d2fb6a38622b422a6cce51a9527764dd6e3f681ee83d3664fd17cbe806688dec6d1b494ed77dee6579fcdc79c");
            result.Add("en-GB", "df00f9638082bc0ac4eb74dd4e6618db669d4e7a3bfe49987107d1984d897858abd59c5c5bfb0d932e3572242d48629060957000c2959cb498991400c1334f9f");
            result.Add("en-US", "dbdd9143ffdda41fe45aa8d56fa1f1b638d8517b52896d5a0c76898399f48f577e6ad82d66260086d44d6d89830af6542b98a3240054e42d8e84483cf191eecd");
            result.Add("eo", "5e437c01ae670b2f48dea2748192f917609690f5d6d2adfda6c0e3fad1851c70a2f0e27fffe2476859792afe50e57cbca1242b4ecd43ecacc2508e8f9abf16bf");
            result.Add("es-AR", "56ffc36cdeeea849399f496c5b53f43627b17aa8ae6f949621b9b5f9ef6bf89c0afe61de33d6a6202f95682499ee4b8fa5c81e8b0f53d581ab042c6c4695c202");
            result.Add("es-CL", "224c794293e6dc5edaf5d24b5ef348200b3002071a590f9dfde4445ec04c72753f154dad4812f6377fc60d8fc4aaf5f81e341d93d1bdec7c61084f89e6a93f1c");
            result.Add("es-ES", "9a8f3f8de61de758f4e5eaeaebc6dc701afb710bb69e5ce18d9cf14ef0a0bb8567c11bb9ed38e268df3ba32dfdcdf9e5e4573a2879b55d07db98a4c6a3f6515d");
            result.Add("es-MX", "f5da7b4c95838c4d54ac9083620dfc025ec841aaa81f9e590ff811d451d0b27ffa1b94bc343f5a90372f5f9e2da6e2f3cd083fe22e12659e84d0d200d4c63720");
            result.Add("et", "e13b71e1ac5da527a0c0608d6b5d5d112fa6493f5f70afb009d9b15b5932e5624ea40e95fafde9c88af8d6520c5d6da384925f08ec253f7b9d8ba8aa03947472");
            result.Add("eu", "b07ea1462b338025bd66d2ab8a12e3564cf5bf9731f802f896fac6c016bc02e775f511e64e0cd34cfd5379bd6d20ce31a349c33f933733eba90d76ddaa08d8b1");
            result.Add("fa", "bfe9cb26d54f98a648ba51c388893cb6e9ff75d1c9225afb03b542671fb7fee22542c421a80a51e2f581b6e75161220a3dd02bf47217e2a14ba822f1e23dc62d");
            result.Add("ff", "284ae9f8177c1752bbd7eba1082c327a872013a91869d377b0fea1db07591dd01ad5336f59e49dc99aaf9bb46a48804d504da082cdb930ed53d2948ffe215065");
            result.Add("fi", "dc47ca3de80352c7b207da0c3be0f184cf53ab5859043add479ce9f28d7c4414d2865fad54b158223606bbbef3e7c1ee1033b70a8128b859f881dd130197222e");
            result.Add("fr", "a1cb917f5ea103802699c945814491f8d6ad8588d735c5882162d38f46bebdb52bb5bb7d6ab037e86b400f37d848778dfe828639a4b2437eb260033012d13033");
            result.Add("fy-NL", "c72b4ce8905d99dab6e15aed7c67614e6c64452f69608afeb5fb95af26fdfb00988bc92d4a04f956a8ac7946a4c3231ee48dae62ea12147ded6d72096dd403d3");
            result.Add("ga-IE", "cfdfeafe9ad811929a49e8fa9509d150e67a8be924fc95b4ad076e7f2b026fd7535d72ded3865c0e4a3d2eaf8d1d77ceb85a8825b839cf874822dddda0b1298e");
            result.Add("gd", "ddf56ce6bafca562f58b1ad35e37d72c572e92d1568c916067a1cf805e5570ddfdf2977d27a7cbbaefe4e5cc58251ab8d5ddac3c52de756a668665de3f15a252");
            result.Add("gl", "fd234bf9c610c123069260434d3ab0d9aad4647ae48622774776b2e8d90876eaaf62317ca4b7f43a1d7b2a8c463024094a979c770bae47ea77ac6dfe67fe8bba");
            result.Add("gn", "f74a195a878ed072ab518c1327319777f62c3c07241f6f08e9439be37a460fe97eca1a007e334454c6ab53e48309396ea3dfd29b53ef2b45b06c259f65fb2cc2");
            result.Add("gu-IN", "f632149b44ebf59c9d4e2e6caaded5e82701485852f3f8e1b66517c7928b777c6c43e69f371df5a9be17d2605b7ffc19cc4f207ea5bf3cbf189dcfbb3905ca85");
            result.Add("he", "f4ff06a86ba7bed9e9192d76502fb5d7b207c2d766150168e56cf024644739bb75430516886f0293abef85a8f39d657086332303abd3ba33e9e86fa1d3fdabcf");
            result.Add("hi-IN", "e32732446e187dc891c9c309b70c64c5fbf9b9b651eb961549d22557afc3e2430542fd7292a040b0f6506c2550a80e44f10cd535496caabb6d729ddbb855b143");
            result.Add("hr", "2ad81f085a968dffd4843be68764c122fe9b97f7177a94ddfa90c503d44849fdd9678354484abd8b43075b345270e9af7acaacc69147da745942d15a587ee772");
            result.Add("hsb", "eb6957198a38a7b2056fb7ecc98290674f78c258dbb163ada750b1514f3e6ef50483b688c9aa813cf0efc2a19376f9df9aaa142b734ff49e78bc1d82a330f616");
            result.Add("hu", "c04a89abd6a5b8b7877aee2abdfe98b54b62c55a0d2acdf1b17a12df24cc66b0a57dcc8faeaa26c1d7aa701db36788d822b4987561a53b187fb8a97ab7ce7df8");
            result.Add("hy-AM", "da6954f43f2a0727dc344e112af278de580e3daeb2516beb1299fe71e4760cbc9d1aed7ed3142ea8e064acb6097c2f56fa7fdde9154ac4c3c24bca3b53725f24");
            result.Add("ia", "434c9f86ca9986bec0589ea70c9e0338963c29ca6adebc5e56a6d09f3a91faae0e2d3791a73fb5cbf9fd1ebc3c08e40560e0bf17a6c7418d3553a7a67d4bf2ed");
            result.Add("id", "cfa862909a7219d2a23d00674d16ae63514173c67df133adec0c2c295d03345396ed1f45f080c04b99acac86cfa2f1d5493a7150e504d4ebafa1e98bd5c92362");
            result.Add("is", "30282cf587b90e9d6fa8bfabcee561c8c12bffdd98045634c97d4ac88042916ec77e4e872357452ac98bea73a25b1b799f213a9df24659a0a0f34da17b908507");
            result.Add("it", "93eaa8da8c05975302a4a9f6321d34d72f4f6afec59966b6ccd1e0116c82e6dc63b4111a1816a2593386f5fdbb9205eb37ccad5a6947cc9522954d2e14c94359");
            result.Add("ja", "fea1d7376b1385612441e334d8be3e129a77fde6d54f164911f16ac5f35710843e9e7aa061a93d53539f7d51abc58cc91a58e401ca9f9c36bdd8dda4a2f2207e");
            result.Add("ka", "84b7f1dbd856cf8911b36464cebfc1b5433ade63541b75f62992192e58d117fe648d52dd4329947eee319de9fa2f6391ba6d63713710c436f91c77ee2b6eca3d");
            result.Add("kab", "979c4796a9c521f729d75eeadc5f07fb9f2d51bbbd13e8f92a20ac78d1b2b25d46f707c36da0ea9edee1372c70dc73a6241711597cc7a3a2b15038c84ff93306");
            result.Add("kk", "17c8094ae6aaffdaf9a77dd902824e7409f9742503031e0a19dfcb38b7a3808b6b0cafde652dc4dfed862ba21a1e391a2d82a93aab5e51cd437bfad1ec9680b9");
            result.Add("km", "2673812d403d29764679a59a7bf65cb6845cef7e9f91c45212a32e4e215ed4ae030b7503b5d0fdc5bcfa265cf2f29f65dafcdc2acf004932f266efedb54420f8");
            result.Add("kn", "1e26eea4473a65ecfce2ca759d5c9b03bcba937c49b6547adbd6dee2447d6a3a48331cd2cb0e8190c88304829536b83f71f28dfa435d5e47a35f252292dc71d6");
            result.Add("ko", "fd1995dd04d7931c7b93d71bf0bf76c681bccde42395d876916aaa9ac4dde5d575dd59c261371d4b8dd3a3f296ae9a57acc3c8594d17fb81c735b50122ec6459");
            result.Add("lij", "da03a2a1248719e4729d6def9962b9e3257c5020cd23261a308c147005de5f154e9c2f8945c5f6f9169f385563ee8c058266700975cb0a66be56df0d356e2423");
            result.Add("lt", "e64935252372a7cd922e486599f76e702e4407c36ab12e59272393a5ffab862b820c20df76880fa2adfdfea7518cba1be07bc1661c730b09f2f75d989f2c9ee4");
            result.Add("lv", "7446bce8e39f131a4b84899258f386da2b7f78d63b7bc51aa07078787f4daef427687e7787d7d64aa0a49cdeea4ba5bf430a28eb608265259317aef89b6fc96f");
            result.Add("mk", "d77fd8557aabbb472b49cdef191668d12fbc0c9e27d23da476d4fe2788a1fc337cefba652372a01453ef5ff290e0b9847cf00cccd870cc6ed5b8fc2bbff9a1f2");
            result.Add("mr", "54541a4aa10cb90fbf282560ccb3deb9333d800e924f7f1523ccfae72965ef3c2a11e1dc3d76908c3714720b80f79fb85097c0c1970d2e7ae885d5210229cd0a");
            result.Add("ms", "989ee732b8747cbaedbdb6c3dad904e2e2918a94a4594b3c77ae7fdd9cac66917ee9b13978937e52f539c0fd07da5bfb3bcbc8231b275a1baf9daff91ddb70ca");
            result.Add("my", "ba746b2f1adce85c30947eb123cacb8d7ce2ef938553c3df06b092495cb7aafbb59cdf00b967c60fa4a299e3bede00aca0623c6740355216598459e55b8269ae");
            result.Add("nb-NO", "4a5fc502048ce38f61298dffce2814b6c5603ca884d207adaa06ef5a2312f4c3494e7b0855285b8d6307fd98232771152ec2d426f525bc514b625ef635c1ca7e");
            result.Add("ne-NP", "40c6cdfb8d1dafbff7a734abb0ff4ad6670ed32593baca5b807250fa2570e27c9022478795708a8a4b1e71e3d5fc8384a4642f75dded5eaa3398f25f893bd380");
            result.Add("nl", "d553cbc711ce24de2dc5d0ec598c27c4cd8986a159dc1afcbaa3afb9e693e6959d6555f3e5773573e04e659cf67f6cdbcd9f1151395fb4e674d6b2a7f2d1ec42");
            result.Add("nn-NO", "c93027fc52428d8ec4f600d7bd9d77f756e2045f80e5da967f29dbcdc1f557ba146fc2aad2fdcdc86f9af9c11cd4ecd811af5b93642cbc08654859cf4f97c749");
            result.Add("oc", "d146487aeb59eed102d07220214ffcd87dfd9b2ceffe59eb672052b5cb21e57fd8b98da614475d79dfddc1d9a19eea7ad57a274b134d7eef84eb734e6e09b1d3");
            result.Add("pa-IN", "5d24e6d94e7e2aaa6bfe03c5a3636f9e9ac884d00990b9a7cc92bf9f742e39a8c71c842653ee78cc00b079eebdc327b9332fa8cfe5284e0acaf049e4477812b4");
            result.Add("pl", "004350310d9e3432da6e4e83adddfca192d86f826da34c8aafe20ab36c0bd8d9084d78a7ac6f3f21c115be92815859377806049e7eea2aab4c7b22f268ed714d");
            result.Add("pt-BR", "bd6a79c9ab871f652f6bb1753c76688d2a5433580601606ebf1ff75192b0660d171be09ed4b3cb4bf0560a5e8731e3331bd6ded6ec0d1f74e97ad7e95fc60bb9");
            result.Add("pt-PT", "a6483dfe7675d329f87d7a64566e0d9f5d1f935e9f1b5823b132113cbe38fb00ff8762ce1fce9ccedd8b3ea0e1aa7fa1fb35d09b32ff7f52b521fd392cba48b4");
            result.Add("rm", "8bda8dcb684e050608b0d3ebe6413ac942a6bdf322c95ed28f0c9efe74281f7db2f45074a4cab6c40369f6026008657a923040e07ac35d3ece698fd4698ff3e3");
            result.Add("ro", "049afdb66d521a4b6ac14dc9a76e10e9a4080bf261f8faea95441a45ba564110c40ad58c106e1e14bec59f43ea16b8a0537a5a715e3eca2d041e56e120f98897");
            result.Add("ru", "1f3428216cfd39221a205aaf67e7ebdb18b229f20da68f640d22b987bfc64fc25f1af24e30da4d1a2b2f719926012fe9e0a69c9408e50251bfe388bf00853504");
            result.Add("si", "e45fe42bdaf98d31f666d3da98b57504ba02c3e6f49dffc982097d11aa9dfb63e5d1e20e6da85d9318a528a3e2a91ee5cbbef15200d94618307303be5d6c13d8");
            result.Add("sk", "b98974305afde24c5f526f3cdf77116200930db7445dd201e0964636e6126f374338f681f0f201619cf10bdefc85753ac137ae57850948011db297099de0c402");
            result.Add("sl", "5f41f30862ad87d96ef4bcdab8b0f9f320e6d10a78b3d1ccc4160e92a3a6fffdadbfc5f8cbf5c3d3496f5f038d09d25ab0d15c6d315c2eeb22361ced6585dacd");
            result.Add("son", "a05e3228704f218ed63d9b35fe99b87f2e46059d48e5f77451f5b12ccd507bb7f9dd9123abf93e50294e58546555797ab7530177a0b20a8a1d57907a116c39c6");
            result.Add("sq", "f88c1527147e135fcb29b6732b8237140053ce45245ab1b243645dc78b60eff2a8ca51f367efce1c008f1f2659a2344b7c5ca8604225b39a75b06d5a481aeab1");
            result.Add("sr", "58bac9af556f6e13a6db7c1f2e448b8de8cbee47994a70148bc15d1fd86446ed2f155f243060b6f678391399907b55a4d9885a3f86bc009849a9b1ffbd9e599f");
            result.Add("sv-SE", "116389bf2a171c4e98d2b6ea521352dfab6cd3b65e9bda1580fb3454d4f043add8e32fa17f8bcc96d4aa86b0f3883246be52916d8883f86d27a15051560a3caa");
            result.Add("ta", "690e9bea77ed644d87e237b8e561647253e492d50e4ff7572e6cf094108a76bc9e440ff592807da43e47e78d996dbe98b7db8d3a148720548d232289d6db2a15");
            result.Add("te", "a148107cc968cb40cd666ebc7d4556a25e6fbd85b45b6fc6f71b2a311530bc3181f54714aea0e54ef7ad1fd71940c8e7cec44edd1d5be438bd006fd584310e91");
            result.Add("th", "947d391f36552909bb00b681dd12692ea3f3b85a948c63933e4a11d1635e8501191e6e951b8e10f83b3e2556b2d962f01dc69c5d3977904a22b1c13d8653695a");
            result.Add("tl", "d594ce698c50c9c9c4e2235b510e16045cfbb805eded0c1f0fb51f4654938030ef751369927297a44ef78386c6ed0217db3752d7ee258c7ada2990f3dcab3a2b");
            result.Add("tr", "550f3fbce01e093a640d34eda938bf92562f4986744a13e40fc5559b36df260f5aee48c144acb295d726e6d77aff18123a30fc8cac6f8d348d01db4c5aceba47");
            result.Add("trs", "8f4f4e1f5520a4c058fc70194ab1c9811f410811148749b1c5f90506169c26e81d1cda06a847a1420930c3f9d501efb815ceb37b6afdf3f479da07d260f175a7");
            result.Add("uk", "9cbc9dd20f4b3786338dc075198d00402353589204c0c2852a24de18b5ee0ae0eea698415030c88af3e5969f06344776293ee5e0178edaf5354952dee9757584");
            result.Add("ur", "97c2e876d5369e8cc0f11ea0118fd6b9f723cfbf259782645a0b232d8502497eae6dec6757cd55df41874e72c64f474e20107d79c170de0da2dd572afe0d1044");
            result.Add("uz", "3c2a907adfcd9c4df7ffb2f03b748d8bcecc5cf239ebe8cbc822355902c02ebca554fdeceb48c9c2b398a52ea0ea3a596b14c20fa64a480830ffb9619c4193e2");
            result.Add("vi", "d634aaf83e336fc22bf928d208b524911c2e7295e88befbe32ed960116e0c09164c3a771f083a4b5a890a954fe76ba9fdd6a2324c8aa8e848c10ffabb42557ba");
            result.Add("xh", "ef9be1d0fbc7a62354e9423b2d92623e08488de1d95b99fada6771bb4863f4081b841353c4f5d269ddab21cbd011038a57b9b96b86e271562062e838a2e66d47");
            result.Add("zh-CN", "c3e9de93c8519f9d273c56a0bd5f825913980116e5c86415d7d209ce5ba60a65b79e4674ad059c17010762dfc763404b6faae19a2ea7bd173ba52b133c3b2d54");
            result.Add("zh-TW", "015e5c88d260b03b52e609027b2c8dd7d9c8dc74c0a95020d29b9200cc9485d530726aef466c807dc53a5e630a98d4f60503a62e4e8faf726387f3192793a65a");

            return result;
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
            return new AvailableSoftware("Firefox Developer Edition (" + languageCode + ")",
                currentVersion,
                "^Firefox Developer Edition [0-9]{2}\\.[0-9]([a-z][0-9])? \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Firefox Developer Edition [0-9]{2}\\.[0-9]([a-z][0-9])? \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win32/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    null,
                    "-ms -ma"),
                // 64 bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win64/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win64/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    null,
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
        /// <returns>Returns a string array containing the checksums for 32 bit an 64 bit (in that order), if successfull.
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
                    } //for
                }

                if ((null == cs64) || (cs64.Count == 0))
                {
                    //look for line with the correct language code and version for 64 bit
                    Regex reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs64 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum64Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value.Substring(136).Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs64.Add(language, matches[i].Value.Substring(0, 128));
                    } //for
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
            logger.Debug("Searching for newer version of Firefox Developer Edition (" + languageCode + ")...");
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
        /// the application cannot be update while it is running.
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
        private string languageCode;


        /// <summary>
        /// checksum for the 32 bit installer
        /// </summary>
        private string checksum32Bit;


        /// <summary>
        /// checksum for the 64 bit installer
        /// </summary>
        private string checksum64Bit;


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

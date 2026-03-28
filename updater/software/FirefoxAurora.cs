/*
    This file is part of the updater command line interface.
    Copyright (C) 2017 - 2026  Dirk Stolle

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
        private const string currentVersion = "150.0b2";


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
            // https://ftp.mozilla.org/pub/devedition/releases/150.0b2/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "c9bffdc1555e00577c341b9e3a8d95d817e966c091058d2f8baf97c3af65f26dcb8cdbfdc4d13c2b48f83241af0995fb4563e4efeed871d7c936d1d8014170d8" },
                { "af", "cbd0adfcd6e3dfe3e23f6a297709060117a1bc6b7befdf52fe891eebbc84ecdf9c44b437ac176b7af2686b7118f73934af53036775935f3c876887080a89e276" },
                { "an", "f2aaaf5d1675ccdfcac78226aafac55adab70eafb62f2037205f89c28895358f11943d2a47ff9a79b7e02ed1cfa8dbad2c7f3b4c5ae800344912e389bad836a4" },
                { "ar", "a860bb824f6677deb43dfd94fa1131459b2cb5eeb9dffc9a5db6dcff30d528838046cd7b3237f739bc715d8b3a915039a8e91d23857bd51245f9080dc1941903" },
                { "ast", "bf1b6c63f8868c461605d8fad5d9789ad64613722c8be924584969e072a17c44f04db6beed216a5d50f03c13d48d3ac4e921e3401e6240425c3def5c45f74b2e" },
                { "az", "ea1a25a82f64a4527127320489c9eb1b4e2daf79b096e9cb63415cf77932787eafc3ce063564142d9fc3b1fa3e30d7c13c7d3c5770fb3d308bd2551a21471216" },
                { "be", "30981a6b3171919f1b0f8c593c5b2b9a7f9d80f57848426cd09f1b8cd052eba37bd7b6cab0df6844205076a8477928b747f83bf2fdfb3f1a04e4a94087b60000" },
                { "bg", "c695bd4ff68561c7fa562b7fb954f945dc8a53032c41cc078907638cb9a4d3f2da8284ee90838ab4d02a878e0683284a9caec243aaa562b5114afb747d275e21" },
                { "bn", "a4b70a3ccda3e41292d61ee53c091d7fb624e01097a6e5200a967811617bdd5f78a58e7d7287da542e3bacd4b4351480ec2056453237a2b7a38ab6ee59a2ed65" },
                { "br", "6a09c6455d6a65beec9f27825883c16b08553390af2b380937237033d4d2b64f6a4d6152efc8669ffb8030511df617f8f3878a639976aded21bea3c0cf2594ac" },
                { "bs", "977b62eede75c99ffbe8d79c606cab4a1c054ac53bef4a93157bcb7c4912f376253f481fb0207f3d5d57c925350304460f554fb53e307a53bb72116a81752b81" },
                { "ca", "19e0ec4b2460e0016dec7aa7329daec91e5cb956cf1167765d554bf2e41537b0a68a1e27d04de666d4a73d8b2555da97cae4ac2dbf55d6e66d8a0074aacb0c15" },
                { "cak", "cd19198fa51a0d510d50fcc347b7c9826e936d120a32a75e236fe4efbc635186ac1a8101c49f3bb5c4c964d59ae228d56729cf6281a8b6b9deacfe0aa1126252" },
                { "cs", "e36dc1a2bfa55494d8b31258e0861cdabaf5079c39fe1f11e4046ff6a2e9745e44898b046a5da53ac9e54636c52dfa5adf5d573afea189079b14c14a9200dbc9" },
                { "cy", "3857abfc27d15d1526f31fc8f6291d5d13239dfeaa37bdf88e7a65a9f854ce44811255f103d2e6e8cb178696ea39c0d72e378cb0996269bbaee2af98838c4dfb" },
                { "da", "adedc472d3789b040bedcfe5b5af8b6e5faee3f1f5497cd8ccf1615eb7089b732556fa207515ecbcf1b8d0976fef75fbb3def503bdeebfb9b38e3e4d46932bec" },
                { "de", "a25f49a5d37cc6a212bbac46672a70ef685e1b7f472ccd65cc93397e299ee0c9a7f26f6a5b4f0bed7645a68f0d866cdea69a38454ece398914663b375171a13a" },
                { "dsb", "c43bf851f3833d743799cc3d30873481c3460751c3e2351c2436a7c90d13e1e7d88499e6ccfb0a60a3d16533c978a8b35aed03c68eed7d3f7be1b3a2a91d3f8f" },
                { "el", "e1abefdaea3add12feba6a92f085cc748730dd38b2cc795dd99333c23b4ebf41a03a77fe5a0ca75227496cb8eb268e035e36e7b78fe617f1bfbc33a3ca6c388b" },
                { "en-CA", "4bb7f17caed2f79b2fc3d713a60f2e535149824567f410746facc40b665ed111ec785e6ccfe5ce6125ad1dd324cf766ac4087b0cced662a07a5b3e27412da204" },
                { "en-GB", "7659dbab5bda502222d9c63fe70a92a1d50294d517a2ada62323f5344888e911f40244a07ae016c8ecb7a1e917e54f7250cab94d21b2abfb11efa92e782ef983" },
                { "en-US", "9afeeffe6c0863c0ba9b8c797d32b67cc501311815b925d4b5fbb5faca7d5d01e9ac3c4b485ff58f5d3f9a004e32917aa433bc79bedac9b99192270493096d44" },
                { "eo", "3900be7f8e13f4142e7702ed00dc10eea2d577c9b96483355c2540e2551a0ad0c10acf2df441781acdc240da744f44dea939c52a0f16703403bacde9f061400c" },
                { "es-AR", "da66a23d5943246e7165508e8c903504897e99c6d037739f29be945ef17fff9a85e26f61a67ed051a2b3df2aeda270448ad1cab3b10e3d1c36744a43cd479d27" },
                { "es-CL", "267fbf0a7f0f15014cf5958478cbcde87c22b96eb01034ba3283d0f6fb22d887d754af2f080ed4954fccd5d760586978f025223618547fe06f6009582fc34e90" },
                { "es-ES", "65f4bbfa8d77f3cc28b7621057b2e3ffd5130428e6db8201ef843775453e95b3fd109e8f6c243d794517a8d92931f3a48aa0ca1c87d129ef909a9177c39d1fbb" },
                { "es-MX", "62162fd4d8a492a2cd8a545a05822cd21fde3ba4df8d3b301566dfab0c8ae2eebd10914270657bfaede2a046efbbc10568a251e3381d0b803724e9ef48a150b2" },
                { "et", "1e9db00e17f360af8aaef748d2ef3162ecf216ed8d49f491e036b978e62d82b392fb29b941734440bf4e2a36790ef41eb544c3825c4d3b73f8696465fd7b7bbb" },
                { "eu", "a959369ea121528cfa05e4a2c775250ff95370440e3fd68b10648a96c2a71c89cdc488bbc9798c3af141d8dd8958297424bc2deb3b92d67d8135d252c3fff700" },
                { "fa", "54ebded57c4f054aa884b8e5118a0445abae042e264fdc5252d44eea0ad08ba849aedc6d9f7cb234247d8e72bf216f3151a730e7d8b5759e3a51dd2b8bf7dd03" },
                { "ff", "d858b3b044724b085930d832f7fe92a722ae2e2ab61e9c13c4de6da3721dddb4b4cc57a93539b0b4a96d6667e8b85b39ee4f3407997f5ac5da2b130a9873c8ea" },
                { "fi", "c848d92e74b1edd76a13b1f005d81a12e6dabc896d055ec07bc918269f277b447434c4ebd0da6551f0ca9b1f9abb60858989f09606e1b15a6e29d472a9aa9a63" },
                { "fr", "2adb0f6635997c458cb7cd28ac1697a6b4e5aee1ed84dcdc8ed922a29060bf8e344ecb6486ae0abeba148f264c4a9fecdf9706535a3d66d5024f6510c38f507c" },
                { "fur", "16a02845ab37e673635f04568ad3b6241b67ede583bb7263a6cfe163623aafcc5c254f1980c800450c73e6d5d33bab112086200a0b4035a78404d1dc21d68178" },
                { "fy-NL", "a7dc002f8f19e908abc41cadd64801c1b96079a3762323771b9690da8a60cf027a4653bfc8d5b720049abdb2ac79d1ec1c71161825b1b746b3930bc61d446c9c" },
                { "ga-IE", "4bdec020a40304c9a97dc538b9ec9df56ce223a48de81c8576676c67767f3510e39c9fb2b3344d452e1597df7324876314ef93fc48434230e97de9f05f0e2547" },
                { "gd", "d16e0766138bd6780d556c9d968aeac1185f94c3a1af60b0ea0545a64650c9378127da060dbaca486b1e40a8715042ee5af920376c075d36566d269823aba486" },
                { "gl", "7b04e6c9504664fa13b1184b86543622b009962bdd708d1b533433d51294fb4c7d965f84c102266e5f884a7a7c8220b39bb27b7490f3a8c8ef7d93bb567f15ff" },
                { "gn", "7127e723f5c34e71e7e897241f0034ddc3efe4e53a44f2955184d67d748668fec8930fc62196b5a20714bb071189aebaaee45b773bd14cba583841c42c4b5021" },
                { "gu-IN", "678fc43cb0ffffaca9fc6810201c387a0892db343c56afd6fa8fd85c4ddddc42884b64815f9cdcbb62cf47fe8668aca4aff09826b2c0151d09ef6d9828b256ec" },
                { "he", "53b5bb0d653f9e676e5f444a51a63cabd63f530ebba272751461e8066e6733e49bba4bec46396f778509152fc248505bbcb8f0e6d511b0232cb60e069f79e437" },
                { "hi-IN", "bfa11465a51a0c51fe212b5af038a34253a6a4957fa87a4a7d160c1ee7ff8afc3af4c1ae4ef2da1abe63f91653b12145aad06fb2af6d7c4a5e252e8ea8e6eee8" },
                { "hr", "a58afb5286518cfe8aee6fefd6a1d2b4d07752f3531ab8b0ff31816ba4dc0a472bb5bbb16317bdf884bed06e9fc28a56e5e79fcd27f3cdf98994f8db8cae5710" },
                { "hsb", "a8b7f700b0dce2ebd772c3d054e0346bd68d1004b1f54fbfc55dd7776357c97e70260947722572e669263f7977dff3c096f3ac303ff578f95dd1da75e8ed28d1" },
                { "hu", "e450835ab99939fa681eee3c177f275a4c8f4344bbef2c158c316ffbbff0ef8dd08d13807b7e82ac1cdd2835e40ef7bea6c4494d07f9caab18b9ce86c7e8c6df" },
                { "hy-AM", "596b06e56e08c5edccad95fb5ddbd8d8a6464632269c5b81cdfe92bf0bbdc6796a7216806f82664a2e7240c0055de1c583b79038ba1e6724be16a0846bad7eb2" },
                { "ia", "12a435aec1a50e8d7bfa8377a8b87914d62da9d41b1e05f650ae853bcef0fad614ea4ccfc20fa583f52ef85370838db27a4c5421b9792e748bea4c8be1bcc2dc" },
                { "id", "137264f4b21724d7642c6e176cab94fdf697ecd56f9a8529edf6250fb9d8fb55ee9b47618dbb2cac269263ae03a134ba57da135879a01fc391ddc36da644c8db" },
                { "is", "469157c398f8bd83f76015dc0d709d40736457977bcd4801053c9a44b8701423fa0e6a9e58aa69a9ea63ee5db812122fba95c0b26ab83876aefb3f756915e5b5" },
                { "it", "7f119ab531f8c5101c91fbb129f488afb514b8c6ea0ca0729d0142c70c67309c9b2e552c7715807582f3b904fc0189a62aba1f9f68e0de44ce88d9b654441a46" },
                { "ja", "4a8d9457b037081e6cf278137bd0bf68fa2173ecf63fd5b7ca29366e9102d7a09a6b3cb8d7a8680cf5ee0c52438604874c57d2f7765ed34c0b4297863428dd7d" },
                { "ka", "2ce74ee4c8afcdfa4972f06dcfd87396965c8d3c09202fdb4c43e54f725cdd5795669ed472e5985ffc5a51b33b06e7ee75c6411874b3a08e695d5d26eaf77830" },
                { "kab", "8db530e075a8e897b945c7b17e6064e1ffc991db57261b712d37b9d7008b7e807c1305a31aeebe547b47154107105e6f9aef3b1168153a76c0972c3f0e1a7f9d" },
                { "kk", "f79edeccc2c153b520f88d759a12059fb0560a1e90fdefe84ad44f0612fc4a315b162e2f21f6ed31806005b2b8d21f954528456382cc1a71bf36d0eb23d18fa4" },
                { "km", "8dc3959b14150bb2454ac9d77cc842d148f82a9c1e589283e2af1257192c55cf56ab1c669da26398db94b9cad2f596f4773647151d63987194cd6ef2af135271" },
                { "kn", "57d70bc98e576635ba2694b4031d930f196ddb546a52ec358394353a7a9546040fba44318b3a92f3e5c788729eae5d803c7a3d8b684bb45d5a59166b065db326" },
                { "ko", "88f474a18c048ceb6141c3afc0d68c2bd5f7fc9c583a3184f824c73b6fd4ccc03e512e432d18a2e881468ae4f4232d1976dd355d196ccc85c908f0196dac3566" },
                { "lij", "60b544581c666eb3670d7cf0bbb83685b0d79f497796de920854b8aec5e0719cacdedfd234092bddd73cd746d30d19c5afe4ae0192c898e83d69a93404f227b4" },
                { "lt", "8b376c67f3442859fccf1dfe3980363313b52d49f05127c6cbbe0b41d69c68d5cb382dde5de3efc561f7ca24a4ec4dd3ca5f8a7a03dc42bbfb5cd3dbd3697ef9" },
                { "lv", "8951322186eb298e0e85110ec92eb5ff2c43c4a55fbda95548a868f4f1ed1827e9fe3406d5e16ecef1cbf7a70e09036ef85729b6d008d54ddf58903624ef9947" },
                { "mk", "812e854689e255dc8026fc85a8a9630aefee2b4b21827d4067d8dde69511baf3102d48e59286648db929b799c806f9f497b24bf9a55ecd48e04524cb36c012e6" },
                { "mr", "51c61cce25447ee1a624614536515ccf0ed811ed78fd66c6458ce3a1745f7cfeb988ea13295646ae71ee2abdd4e8c3f1734cacdfd7fd422419c24fdd41e0ac9a" },
                { "ms", "44dccf89d6a45e8268d5b0ef0d2a389f5b6dc035f97d959f55c0987b727032a09bbeafcca0f106cccfd30667f2dbfefeeb7e9e3214b68f1c1c955f05ea1101ff" },
                { "my", "b5a2429a8aa7e6f44e0ec6dcc5d5186b5d8ab14136a449cda7471bf2e03ec5d687b8b9dbc76ec6e886e858eb6b674d26e02fa3112598f368a8a843b645121e4a" },
                { "nb-NO", "a039c966dfc00dae3f58cd427c29a6f9b68b8f3920497090f27ac7980bc83bc923afe3ff7bf1a98908f15a0bb8dbf5a0e97896fcce0b930cba5922eff51449ca" },
                { "ne-NP", "a07b231c5a4898e3496408f625b081d171a83056d3e8a5917605aa50b95781d951b8fcda0cc80858f29809bf61f141d32797663777276c71a838405558dc0c69" },
                { "nl", "c33dcf2ceaf5787afb5052204f331e6063ab4264bb8870ae39e24f9bd9aa41dc0e240ddfd58d3313b58d7aeacbe4d9d7124ad639885c15855cdce2c48d7a409b" },
                { "nn-NO", "9889bac043921b281cc38b73a5f1a5a85a0eb8ea0dabda4a98888f873c816fdd72801b6d9476e301c7809342959e27d35362ca39df86bce2803be0ebcd103a44" },
                { "oc", "a54698fd2e0bd3c1f44e6a13c4f741033a21e0e016b9c2a36aedf15fc35af3c22195dd21bea8c5dbe5e647357208c898eebf1d2206bf88cd7df7d9376b825703" },
                { "pa-IN", "dc5b9215b2ae74fa9081b5d50735e22f7fb0196827a71dcbbbecb2835e285041acb9d13a5e200ca678f2c75467ec4dd5fb6c23df69886fb0a549ba0c0654d023" },
                { "pl", "301e3c631f78e31d7ec9134bcd96e7a0785fa12c40e79dee1af51e7dbb4fb741639a9a26eb27770591336fdc20cbb4fb43170a91a2f215421917c68f639ee048" },
                { "pt-BR", "8cd48bbc6f2f86b8218263299b866083d4474a1f03faf12f5c30a93984bb5a241efb8b450a750a5e22828bedccf6532b65b53e302dc59ce5b2f17f5417e5b391" },
                { "pt-PT", "ccf7512791894d5854d52356271d8da6e6616d5a79e30342fb8cab849f83dbc9ff650b8f9536c400ce653d90822420b8608637fe2906fc6df4c9eaed46be39b0" },
                { "rm", "1d6094e5bd22135deb280b99009c13f1b34c5c4b2c0a3920039083dc2351347f7f10c084d325a3b4c7df75bd487e3229af3233ea128f42416b60c77a79ba73c5" },
                { "ro", "9dfe5f0564aa6ebb86c5d4bf8fdeb603cdbd50281b94cac5982e8c2dcba92a172ecd5fa2a5c3161f1eed882765072f39af0610b124a4e77801cd564d5e47287d" },
                { "ru", "b31f81b3c60ce92b3d2b3dd743e12c5db040c834b627f5409d862f449bc00388df22909bc7c93f82b08a1ee3826c7970119a76b3076f85ef5932f290d571f6c2" },
                { "sat", "28a447dcecc342542d44f20f2a7f419756795ea4773a7bf8ddd2ef8fe0fd6abf87ae6d0fdec5bbf26031f0265c4124c5a8390b44de88061b856cd37541a807a7" },
                { "sc", "e909a84af971ff6083dea01d378fb4e670cb3203596315c49ad2d688baf3a3aae987a9b8803167dea860a64bf19d9169a69521a57f161119717daebe153de506" },
                { "sco", "42a8a0b82749f3c764883cdd1fc39ad013fca0f83df7e523fcc25cff1ae570437294ec424d6f597cd731b00b48200b2a89116719806f013c2ccf59d3766a1aa5" },
                { "si", "671bc97cd8be17c2e2ceec4ae8c94127aff121549f416b8fc61db4f8b0e0936f02167ed016c164e00df5ec5dd6bd274949ddea6410348ac66572ad44b997a88e" },
                { "sk", "269dab5f6353c8554e7ebd139bbaa32e8dbf5580e24af8dd3bd4c6406ca0902a0d51710ca77c9b0fb0c164f8b8c36ec5c0b7293077f8f4ff0c00ed6fb5dd5a79" },
                { "skr", "aacfceaa37f135734dc7c6a83650aa67b8eb6ac3c8208b214c2fb72fc117c6faff695a2ba517433706e36d81eeb2e73b35c43b2c95bbfc2023e22200fb0efd3c" },
                { "sl", "c35da496a9cd0a993b9785d0a795936aa6c88244cbc64f2a4f62a747f5e790236ac9dd384d68d3d535d5dc8c58db1e1b17b576f80335c7e4ca1e1054c7022a6e" },
                { "son", "98dda3931368731fd483138a794deaed0a8ba2185e840f608178bdf4fa4f218f8dea24955ef7c9f6874d86c4499093d33c04904f5dda5b88d3389509af7eebd7" },
                { "sq", "9bb3e54a1c48eaba017b80633c0a763a647c7442ae43e4fb74419c275785b498985a7bf3a151cd624b73cb6fb5504193f1f23beac26c716500b8d78c4ae3765d" },
                { "sr", "6356cb57199b5f135b4207222c6e096b98f941354a953eaf1aeeded8886f5461a82f47dfda7bc8b8af7c7d2e6655b1557756889d1105bbd6ba5ad9c72760dc04" },
                { "sv-SE", "9386b06cfe42197c1def3f3913716fcaf19e3c984568540c9fa02b0a4f38b08576bc2b81d8bafe5955739e64c8313f20346a0962b3ca132daa46a237204cebf8" },
                { "szl", "71bb301c38da718fabcdc5119fa003a4298ae9613e224aa275823fc260f015bc8f44e38ffa62b535ca341399fd2ae0bd5ce1740c469bd477ec7e85ba844907bc" },
                { "ta", "58fe8dc7e63136b56e45df14f98dd1d8d52c53b9a38c9984e54406326344e263381c00e38697625c57a167d2ad8c71f0181506846cca1a38571934377e8ff931" },
                { "te", "93cc283c21370808fdee231579bf6f409bd739c4c852419cf2674991e63d7d39bccc4428dd5111413b8d1fc1713d476fa0fd504d91596fe936737a22acf6de28" },
                { "tg", "200b2bfc378d843dcbc32143b9cc3d76d22daf94f514d791a0fa7a325b9e84001d8c355f795d778acda8fb4c4bfa968205fb247ae9102d581f488a5269869057" },
                { "th", "f1b58c48b024426ce20a2872e4b4d415b3f39ba804a8b20e221167049582f84d4be44d26d42ca5343a1004c671d4dfde13382e685c18586dd6db050841e2833f" },
                { "tl", "3c2047c025b2671aff116527ff5fd7a6109670dc27f0986580291bd378d270fee2fd85fde985619408a4a50cb712a58f52b5f8844571aa6f8d87bfeaaccbb001" },
                { "tr", "ab4a1651e3b9c4c3647b1e16d1d20715db2e71bbf19e885681f3f0f3e069600eec125b741b15808e6f11e5f54473e95b927fb36a18927ee5f0eaf4b3677297fb" },
                { "trs", "3e1f308b3734ad75fa14ccf72e755ea84530438aa72eb19c07a5e3da58905ccbac88e95ebe40bd1c43820bfa09c52bfb53cb199d3c8ef215726c9c49e7bb3347" },
                { "uk", "8d96eb4418bedd9e31c8816442363967f4af96d5b1b6903b474647d43c948b5458dcc3ef9eebc24f481c04e32db054cdf17870e8047d72272d07503355878c28" },
                { "ur", "4673248f0f974ba6f7deeeb22bee2ce72e295f8dec1e1697236139530054c250aa30cf546810b7032440b5a136b2410e8cf6925c96f105ff0be47b2eed399b28" },
                { "uz", "14e84955088fb9e74565dfb284073b4ac2b10062fea1cfe727a1458c1527788fd08077811b2e1340bbbb2fc383a7a7cd96566fdfb64d32bedcf120ef214323a2" },
                { "vi", "83aa19824947d198c9faef9d277f84e72c60f40f0c105523de97b50b46e8222f18299d071ff7b511b2c09ff9aab4f3599e08486f16f7f0eefd30fd33853d1e20" },
                { "xh", "f5745da4d6f55ab47fb5b12624826fc859b676913e50aeed93d0818f267f82df6a91ceb6fe60d85fdffed9e3a7c9f6b50e789b9a1b858b379f805c8ca3589bb8" },
                { "zh-CN", "3f073f8257f2f8977ff06c9ef99557ea346c8c10552c7e1e286441c493b38b809b42055cd01fdd87661f66ed0605f6651f4aaa4b5e386c3cdd966d4cc393e389" },
                { "zh-TW", "10e27b25cf2848a2be3d6b9e1920ad0e432476da6e5d6865fc24b014ae263af17999edd943cb873ca59b7a3c614917bbe83416c3d0fa5069aa2b9231c3867b47" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/150.0b2/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "80703be2bf0e439f0f42fa59f9d0916c3b9f2f468867d293c017a4db3a98cdf056d6740c4a62715a547a6131a52971a080cf6cbb8c3fae40ee1a5b465459dd87" },
                { "af", "08cc2cae2c8b60f6f9a95f0ed40e05f27afa0819b670e7f46149c6de93ba8e90b782a18c39d341ccee5da0010d68fc6139b9c7fb1fcb395cf411c29a059d1c40" },
                { "an", "7680012fec672821f4ff939b400bc56e35048b0a1815083110009dfe514de5d56958c592e92d6f218a32d025dedcc93f12a44f6872de7719f61409cdc17d615c" },
                { "ar", "2b89d242c54ca880af3398d6a0ca13c224dd2c09acc92c4dd770c5ac848469e551eb310ba744b5e37149d57b887193f935bedd4bd1a9068253a78d768264b2b5" },
                { "ast", "73f5d81feef9d3ae7f1cd4b78d692e0bbea3e4fdf868d3204e489effe211cb65c35addeb79ed34f3f754208616ebfdf61d1dca03469632baebfdeccbebfc79c0" },
                { "az", "8d1e2bddfef55a87dd47a84acf2921bb40eca91a9d329fd972f2d0c944d56c6648ece4637c0939aec88fb646bea2820a6f6f63a8b2ef8cf0d13b6fb946697d4e" },
                { "be", "71b215068b8fe0bf6352b0069d567c47021643e4aadc0376b5f7626a742132b74ac30e1e06282e5bf39af6d614a9dfec815162568905c1421801edd6b057e9de" },
                { "bg", "60cc95b61130a6ca6fe2c9c96509b307a96531ed22f92c42046f818a5959a6c29fd12a4d0fc4cfa35fe88039496f3e5bd2240b49a9dc51f940ccf35d8e066568" },
                { "bn", "04be2d2dd4c7fc400b806491999fa4c94ed7d1a891efa2243f12d8a3318e269c8efb48ade38fba66861b3e09ddac5aea9ed623aab019bc63a2069027f5439740" },
                { "br", "37865ad45033c9dfb094e1265b184ebe7366759b11d40179464cbda7dbc8b8c45ca0cde5f3fb7a74edc81b93ee1fe3e1c191fa949b78345ff011282fdd87e311" },
                { "bs", "502b9cf7d60c4ddf274caa1331493316b9ad89968a75b2e955b524b4d8c1f6f872837f367ca2546392ee41b5beeed2fdc8c5707ff0a6511c0fe74120012e8fc3" },
                { "ca", "443f5bfa2a3d5a470164f38dd9e1ff08db1f0f97b22cad05585772687c84fd0a5084520ccaa064106b4d278ea24d229ad8da1bd8624d7b5fa848fe9b4cb3d9f5" },
                { "cak", "468793767e49a21fcb8986d8ce32a068f4b90978bd048324619bbe06dd1c3d6b77771d91b66cf88d0fea382868d00f3710accbfe769e4f0d16b7360b40fbd1c6" },
                { "cs", "f03737053b773cc6d5d69ed466b4a6875f6f331b56b62ba6d6211b0e3ef4a9f64d6212213d512beac2f1970800599450044b310fed3a1b3c59d7fa8c51b617ee" },
                { "cy", "e8aa4aafde0e33e29965f1dd257c2614ced5d49d43d249f84ad8cf7f7f260bce03506295fbf78c0669d726be4648e9c74f302769e5861df1fa3a052b4952e5a1" },
                { "da", "654ec2160d88df207dd2e996ba25b60933925b4d823335f17f7fe10d80af80be17992da0a3cc0bc669f5bed20a726d2f0203625f0a3d982927ee2dd9739f4973" },
                { "de", "4545008661c642f2575768b9bf8ba89eaa1bba35f75df7fbb1ca1487d2312a946daa0305d5ba25d3dead7a191389bec10d843a28b63c871878cf113c2e95308a" },
                { "dsb", "3ee5a8ea2473a73a47e9fca445fc8056f7cf290d94ee25331293cd853f548e93969788fab62a09e625566275c2145d8c0fb4c6f2a0628fd0d6b3be17c9743407" },
                { "el", "ce9e4d94e2d2c1efc1411a4e997c003bbff83c0ce768adcb27510f1684033b67e9ca0c00728151f533ffd0bb2ed56f1399957a8fe235e2b95bd245c32f0e8cfe" },
                { "en-CA", "e221d736ba134b948e105039e7b1e13eb890c180e57ec1e7e39c0f64a25c09c61779331cbb4f648f57d5ab8bd9f41694646458c4845b758b04ac4eb4d09f16f3" },
                { "en-GB", "da15fd8dbeac88af4d4044dd47bbc2748e0d31ffca984fa754e38dc98beae33c6064e1775c1d4ee88732bac3def2c9423188417a51be2d90eb1f71b455ceb450" },
                { "en-US", "72084f319939ecf3728469a3c9cd3ff2a10c20e48825c953043f7c2433d690ff0fae264abd526d3b3338bd10365da9265f0d09c19dd8ad4678621b38a761d69c" },
                { "eo", "25a74c8dceb745f8039c8659667ae0ece411aa731714222cc259a29c7c1016f25d8aa2717f745cb5b703c9606afb6c3435b4659e0799d9712841a329de622c45" },
                { "es-AR", "244dde5223f2f678fc9a4a6846db3d9eb4e96852c55113b372c6a331b2b0a1f806215182888ec5509f951652acf0e0e9c7de22f69a0d5df181dc71fd2b071a45" },
                { "es-CL", "aa5d5ce78897d3f074eff1573c14741ecc7b5acbecbb537095ff9e9f99444d8c3a6a2a22908287f2560f9cecfc5f139eedbcdd517c9e81c4966d1674da767de1" },
                { "es-ES", "7ac5c806d89913104457123012e30d039503dbe079e14a88109246a13cdeb8f609f569da82915592157eae10f4a87116c9aa44571b2c00b6dc045a4ba2c4a586" },
                { "es-MX", "5253646951c5e3c620e9a7ea125e37f1ba9527206d28a125a374febc7a3054e8a011ca0e3ec8f0f67b497b18e58e01fbe0d6ba56fff1070b58682b75ab893d0e" },
                { "et", "cdb2cdfce6c9f07f0f1b41424490feeecd97f63d5d2b77bf13fa34bf8032998ab462fdb05b24402968894116c22a550d2eae05e0d9423da46f902ef78b33e268" },
                { "eu", "8b389865a0dfa2cbefb7c87bac4d224c738b764124e2e8e2875c4168096b01d85e159c5b51d808608dd66cfff564d0e79d7caefbfffd50a4cc646fa6f9156b55" },
                { "fa", "43052732317349d49f642728aeac55ae47c123fd54b5f3edaced554b542e41d00a751068892fbb7135c04cbc1793e3d752c789179124a0f9e786e12d25e503a7" },
                { "ff", "75ef9158508c194852b4947b1b37aa0aea9c2cef8b3a7ff662d2b3a9b496a64015b2c09b154a58e5d622ce0461c3923d808fff66ccb6bcbbff4c0435afb9c868" },
                { "fi", "2e90b43888af8a207daa94390f8c3ba2742f5e0443b008efe7df50e49d0979d3dd39f8dfbd2ab5ed15f0957c2fa1fe00fff6937d05d2d2775b96c0c56801290f" },
                { "fr", "da076d797eb9ed7f820f99132fcd576edeba075be72dcd8d32e219252e2d1b3ce46f844d9bb0ef31c4f8a7e560c735e59d977533225fd6c064c41f8f448deb5f" },
                { "fur", "a299d1af6e421537932f9d09e3dc70b7c8360ad8b625e3aeeca225b639fc02bb740248e1fbb2d84fd413491e4928b37c6a99f84672551c49f59d9dc242bc43ff" },
                { "fy-NL", "e13f22dabc013f5b8f91701c642fe45d3d25cf3343ceec5fc3d32da7519766e7a8dea8915b1420b1727072f7b6c7cfe0e37124cb362383339ae26213b42ffeb5" },
                { "ga-IE", "db333de00bcfd971dc718687e249275b3ab08d693228699b1575ae0b24e0e5259d408ca036980a33cc6ad097894c2ce0962cfee1b50b2d3a76fe9202ec467b16" },
                { "gd", "f4b3de78ac2a34b31f52851b2b0f26120aa925c3faa08d681e63206fcd91e8208af36bc9fc9ec7d31a108e2e7f415a7cc0cf43399530388817b124a1c2ee93d9" },
                { "gl", "0bbf724796ceb2c65eb8fa68a761de529f8555fef789e3b1ca48ae40dcab58582b907b4165bcef7c545b88dbfb9443a87a2ec84df313ce45d1c69fe1c8cb0aa8" },
                { "gn", "c3fb3ff5f583839f7d235de0ecb744ca58bab005335bba89965b666ad962f2278ff07b947e65bda79702800518015f36ac5c1b29e64fafca8aab89d101329cb2" },
                { "gu-IN", "03fee8e6ae70f22acedadac1ca4a485be74e69b6fb036a6c44a1b09c9cc03b774884777584e2091b91886acf3dc910a464b23c305f5a8a21df2bca77d92116c6" },
                { "he", "b9a03d09a0da9be6225bf6678917885a400d40ffe67c27480d1989783080dcab2db9302d2c5ed3361c0c2a0f4809ec6146f12deffa529b592386fdd260fd6390" },
                { "hi-IN", "0742697de390c92a230a67e22e43f5d9b201a3f45f484f57199a4e68ffeff37cf40829817222041528cb624da9653ec4f32d8cffa999e9ae327a111172d0b530" },
                { "hr", "1c256d82fc18b154e7dc4d9b29c5a904889c7d7ce3c5101bfda61d004c68a62dd71a107090f957b3d8381ddb5479085f806ad2672e30f1c9a61e42a1b39fc92e" },
                { "hsb", "e8181d8042f39d55ef912fa0ef70a8a67f4c16dc7c042c0cd8a59b93000174e046e552c011e6dfd6cf98999976f40acf376423bb816dba3665fe1850b04cc5bf" },
                { "hu", "dc447f5fa03462e1a0ba2905a44059b8e5c74aa1ae52dcd88d78a265fee6fb4e4dc034191ccf106b3994877ccf398ba7877bb41686f52421700419e923fd00dc" },
                { "hy-AM", "d3b1e2b587103863ae7151cf40da991b9e42f94220543e4a3dd61b97b0187e91ddb136d12782bcda7e2229d7c5e41d9350933116b7230bbef6c5aa96fa7f80b2" },
                { "ia", "8a8ed88954225f600bb4281cc86dd31432e4f01efce0b80104d03a1aeb2c09022524d22f66275babfa393ddbed512e1907b9e7a4b9485250964a1c77e48c8920" },
                { "id", "e58eb2d375f45253e1cbc6885e45b9f2d3923d3ddb1fd39973096a6a1a080d8849c8517e90fdbbffaf441dd54b71cfc60d4cf2b754d772234816b4de6ff35158" },
                { "is", "d8de10708897f71896ea8eb6530c435d995ad09d4e77cc7d1d8139d488e65d3b886fd07f9313ffdb6313f9df6d61bc89fb2c8a4ae5c5493b1343a71d31fa17f6" },
                { "it", "2f1888891b239fe780eef0cba73eac82027082a2af37f21df4d7f1e1fed36545fcc4af623f4532b6386cf8e2135a30b62ada04f95c1f5586c2861f893aa8cb18" },
                { "ja", "cf649531da07ca219d353e67c63503ad5bbe0d9c5068a30fe61d299ba725822cc7ffdb6141de2b60adbd2103c453211b4ba150a107b938bdddb4a8cead60993a" },
                { "ka", "cae45ef64615b817ae611a5fc15e858c24873906e41dbfb5bcc6bbb8c095a7252113b88bc6adab551531da73990ba60a5d11ddd957fb2d779be5cc80a2e79d84" },
                { "kab", "14722b436cd56ee07c0fec37804e0a33afd6b801072ccb1a03899766a32331854d25fa27ff01a93738ca2f895c0b1fc200eeabea7f646ad4ad13ad84fbc4dfcb" },
                { "kk", "e5b45c83d20c4435f0dd8e6d0117eb6f34f6f7778dab88570129517b38a999bd30d7d3bc63952d2a86bd2103678ee81cf8d1ebf40470097887f707848af8cb00" },
                { "km", "e36f8afe91b2df9e8a585a6b984c7ecacca3dcf95fa5ea57361cde760b1b450981c775444dfa29cb9853573022af56278cccef5fdfd25ad1da3e428a3d573c16" },
                { "kn", "7aeb5b82c67087631d6a912ab1d4ac6df5b9830db251a26d4d2170491a49051fe846b08762e31aa1367cd2f1d53866468b11ce6770c7cad7f61677df93a72182" },
                { "ko", "37d70a212261ec42a1be7c38bc9e0bc9c4df79f15e3a6fadc56eadab39b83ed9db8e3c0525de0559d51f19ef838939d0a96f0a073f0e303e1fc58cda3411d012" },
                { "lij", "a68d249495c5b00507a2074b4f4171ce4ff1bffa74cd70981fcd4efe9d674c32f7d8348202d832a359f1e0644ae238ce94b0e3fa7deaeb5ad0c397958a159a61" },
                { "lt", "720b626e90c7a793e879eff0ad3464a679aa8273bfacffa04f0ead273d7c39998dc15865bfe777497cf766b4b7314a242bb54745a5d6a856de4d0c82efb01742" },
                { "lv", "42a9efe537eeeda20eb3081e75baed1375af014aa4d74aad68531a4d81b2b8b040fb856ec33b725ceeb53c675337c30a32c41d2d61d850b4c2f60d393e33b3ec" },
                { "mk", "25981842e0bec878e655650a3e4d149f231d6c7aaa1df6a08811e630fb43bd5d4c4d9ac77e76a5d593e6de4d06d8510823deb37e63eec83682750b41bd7d931e" },
                { "mr", "503e59ed541c9ecf3cfb38d199fe3b2f3b3a2bb64be1d3842ad9e541d97803df00682d0e7fb56305ee406174ef8bb49a5fa40560f0459ef6bbefc1e4f3bd7266" },
                { "ms", "19cee7c6df20af8ce8caa3264c28a6959a50dff08d34a051f8707bf4cbc3bf4694f47d39d6913dc6122e9a7fc05c7322a0976453720046cde275de2e17cc6bfb" },
                { "my", "29be392bd374ee1c235182aa9fe77d6fbdc955c9a8e0bc027af458ae1f215483d404d7add37e3fad6806911f14c003df719db056752303b509121dd9e58a0dbe" },
                { "nb-NO", "6e6bdd468c638b53651c6ef0a281d3e90c25f6cb178c6c4eb1df31173b65c2f3c7cb26809b2a21fedec719f7d27c3cfc6286accc479b20acde0edb25cce399a9" },
                { "ne-NP", "9af8ff3a3ef5961829714c1e7fbc60c71cb108d47e5bfe81c70ed064113a43b80ada098471fdca8aad7dce63f73d02e6cd38a88852dd85f407df8f5cb41f56b3" },
                { "nl", "1cf27121edfeb2740d2f3bc055b02163a2acc2649b355d536f03078e7171d5ee420aaa140c5dad395d891a6edccd16b20f94f37711a125ff17dd74498718e489" },
                { "nn-NO", "c53b158a1acaa38763a7212c3bc498982ca4a7011f2982c9264c2422b9cfbd997f406120dca5399f6f345ed5df798dc305048306e838eeb628232c6946676e17" },
                { "oc", "b0863e06be46bd6304b43798070e9d4d89e5bcbd2291da81143863bac8fa8fe468b4bfe7da7ebf5c693bcef11b144bf935867276ac6a13399350e00a78d7b69e" },
                { "pa-IN", "6486df2554260a273d307d2cc8f31a4627f4f8e7038ecd6bce8ec028cab0aff8944596de48e7a2e7d591738829e73b050537798d2bc79dd2fbb92073e105e7b7" },
                { "pl", "6ee279960362f5c9c55f55359c218ccc6f5a10f600f64ef5d7f25af53df884125e511441448827075b780d6a2f1570421c8abc1d6458b5e0e197e3932f83863d" },
                { "pt-BR", "09c88cb6802d91691078d4baad159c3e14af38cb20aceeb3d74e56013ee068c92dadc97e9a04427fc4ff803f97d7920e6977b30f388cf571127800a879042692" },
                { "pt-PT", "99e8219874cc18ed21e7d9ca66198475886e5cdd114bdb5cd085ee9030062f66324a341520f05cb992a5bff8808864db09f9ef7d0fa917a472027df6c407384e" },
                { "rm", "f56aa44ea251500a562cb93182e58c476ec02138675238eeb76e081d8fbc8d73f9ba0f425425bd2f913968cc1f3181ae1826d86de9eb926a19215208cd9dcd2f" },
                { "ro", "91e421f29bc88d49c543b52a7ca6b57d54b2fcc0c8cb4e7dd5a0c959d72ec9dc61c24c80d2abcce31f10eea9ac6c7a2c60a617236671f82742a33919307d2e79" },
                { "ru", "4f7349284bb3009ca8e56175b66ac5f14ae28d1f341f1d9b26f084ca12bcea5a1e4bf25ffad64bc8a1ffd19e4935bcff2a035b5d6c0dd1ad8c45cc17733867c3" },
                { "sat", "22c1b04a3d320fdc6b56f9470ebd760e29974d46186f8aeed77d2deb906ec99e9c9b697a863dc7d3dbd69beb298e7daba9ee890b0259ac77e320b2490b3f1f57" },
                { "sc", "faafa7d0d77b703f8fa529cc986d01bb35ec0325e9f3148138250718c3f1d5d9760218e19fb501ba096a1a77c424a04a1fefd7e5402d0acd54fea59be06bd5ab" },
                { "sco", "fb061ec1842fdc3c51b231c8bf9382b20d0f3c453106912945f9aa0f0ba0cff2de0e13f821a07f12a9aaa4581dcd22b6b66d4b0734277b1eb3d39a32f261ac95" },
                { "si", "65aa42dbea38889304feb9355c97eebbeb9585768f9c955fcc9c780d12865f26420b1ee8c62b9519ec289c90663ebb16e1fa7ce293949f6239cce45d3ba95ae9" },
                { "sk", "22c8911c35e305ead0220952466b7d4a98b1c4f0cf900942e7f8a8782bd621456d1360749a6b45dcffe277d7b9198dae9f4525d5d19211ae8584fddae71cccaa" },
                { "skr", "200eaccbe77ce1d0af99dfa94d34f89912599403388428e210b672b370896fa4dffb6ae00a901f74ed01b478c2038b0e59eed6188c8dcaf953cb1a8387202035" },
                { "sl", "90fbbe77b76be2e4572993b47759c64add69d8b8a9f0a639d08ae6ffacaeddc21205464cd67fb47c1181dd911ba50bc1101ddc01ba24fabf81577ab012ad7d47" },
                { "son", "4236e91ab35f94a27cfb3ec34824c49dac8babe93062f232ccd59f7051db8e829ca68b2bca6ed10990ecd0d72419b98ece6640371d31737fb64873e2c0eec901" },
                { "sq", "4316fcc2e903a9a9102c21b95f63d2271272cdd3342f0677ba35e8aa47081f312307aac477f967d3309e477f84bcfb538c631eac0848deb8c77ca16b6e2fecaa" },
                { "sr", "16f7c79e32b138333c5a68c6aae1b6124e349fcb05a250e97e4694df769e356b664874342a0e4893aa934ca57450573b42c369c49ffd7308b33add96cebd22a2" },
                { "sv-SE", "9edc036a2da18ba2b2f63959c392539f71537da7963e94f4706b8a4b7d632e1bad6027d56ebe51e2d1c95fa0a3d55d0699bd9b7081da1fdafae9e704c42d6d90" },
                { "szl", "0bf377e4d8ade19d73f6be774339b698466ea1889a3932b0d2413513c965dd04ec3d41d30f45ff9ffcd4a0277e8c12720388a31e108777eb2e92372f75b3bcdf" },
                { "ta", "f9d0fc5ac0aa71f6fc4b3c7877bc31cd89e9b0d2aa069ed56e3b2a8c09ba858fefdaf46ff04bf8a1171afb5052c075f1e96c24807eee0b67734c6a9708b0b9f5" },
                { "te", "b571a83fc6cb0caf00af8018ecb1794a4e812162d4b3969f6eb5c97c5862a1208a55ed27346b88b166a363c76f848c40396ce1bbf4a9cb742665cf89e55ea10c" },
                { "tg", "49394669fefd26855b5d1649876630955fdeeeedc2ae938b9b6923537b1abe6d67c1a18e885a12762f63b52329027bb9bb127b130c21571cb3732a10aee8c2aa" },
                { "th", "6fc5952ca3d9636f0aebbed6c2a6596c564f94aaaf19aba385f0ae6fe4e69ebfafbff3441f0ee29d1b0dc0f50ac679f6165a0664f3b4d728eee8f56e9c64f4f4" },
                { "tl", "ac17c5af3a0879dfbad78aeb8c28434229a4b094bf4a2fe4607fa2c259484382a2ca3023ac83ec51c2d920429a9a736de28816001440d743e4311154bc2c4cb8" },
                { "tr", "4192a1c9129b7c299f97fc80ea13f9435b1ac86438ef4417f36daf4f54d2e262fa999af3fc9d608690615464f164534889176ae3ae2bf066c6fe745223ec754e" },
                { "trs", "cba6998a756a130b2588f115270c09d17e9e8f28e936bf5c83de4a455ccf65722f9746592cad6ccaf02cd5eb0af1e17eacd54f64dab051ea197b99cbf60b94e8" },
                { "uk", "8136649e4ba90a1633e6ffb9fee0ad371365295e89e4a0783fcbe99ce90e88240c97d8a7b0171b5c69efe67ea5e59b3bfb286618db84d6f2b91ede218a46c70e" },
                { "ur", "570a1f649e39a6493aca9e62d9aa5e61bd5b7ae8fadd6bcc3c513f8c5ebb1d85303fb670770fae34d00ddb80684863510483162c263a39585dd31cb1c0a7fa58" },
                { "uz", "12b6d1515de17168800ca4de306fdf1fe316ecc1ec03f3167136b44a63a41d619394eb74ec2b54c5693d6940277d08a160fd7115383758a8b0f0f3ab55ba6b61" },
                { "vi", "380c2a64a3b8e7789a187123f615ad0cdf9615ec92bc0e9f532b7ea93e9e3db8317a5a50bf94a60619bc270e7c309d8247c2eb17f215320223721c5ef5479320" },
                { "xh", "1a7a2c71cf3d6e525f45cf7dfef27866025eefa7931f691a095f3cfe2198db86177605250f522f7aa147a01a68c84c65ef69e18ea51f927c0baf6908627a7021" },
                { "zh-CN", "73e8a1565ef563e23899cf2fa1b6acda26c70efd1afd1d811b9764292e3a28072d2141e837a6df69c5c87cf537a27f4f9d7a6df8d1882886744ccd58cdeda34a" },
                { "zh-TW", "09008a4b98188d857f7492dc29c11d05f054019e58fd409835a2394f14c546215016268c99bdd988f1dd56dc9cf0f29063b88d7f5b72e0c28aeaf0a9841d8038" }
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

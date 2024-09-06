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
        private const string currentVersion = "131.0b3";

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
            // https://ftp.mozilla.org/pub/devedition/releases/131.0b3/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "a606f92c7c5c3af849cdd9dbbba47241471da92f2ea150dd4161cb6bac21bf77eedc5bb71cca462f4b4d0cc16d05faa95d35589c49f677408fc44970827e7cd3" },
                { "af", "ccf67bb9b24788a79b6c09710cd63e2fd3b334256adf05cdb794f4274f3d34d5c19c378b5af9bd3e011e9707ae8419a22b86dcfe77a18627ce837fdd83e224a8" },
                { "an", "7f85aed18e277e29021d46d8f1d6799c5417bc1e025bb1996e70ca23e0d58eff87cf7f65ed81f7d07b5aefe505d003cd5225090ac1d61670a6fa58a0812f7a01" },
                { "ar", "9b6c8f2ae20ae60ab084b2cff908891ecc1e2d7054404002de76ad8c0857d77e125d2c0b0e8d3c17582a6ff2077353a73870e2567a1ef613eb8ba2392da973dd" },
                { "ast", "8a403ca7d01df88a2767b598f696566be15dd1061181f46acc173ec393bbf8738617e349305d88cb69114946a7fd4841d586b0126fc13414808c72617fd8ee55" },
                { "az", "f80a2eb0572683010e6867913c21668e6dfad96ef0c0987fba0c33603073b6e3fd40d0bd9f90fc17ca10e02394417849ed965d9db2faa3669113ae6bbff4b4f1" },
                { "be", "60208ba964f96da148a703496584e33906528d5d668e2e06029aed4f519dfb67ba9bf0e9c1bf47bd4e628f0a67f0cabc554db87aa6aa578c0fe72a04ba2f4190" },
                { "bg", "5c47bf1a49d66f8b6ef95dcc66c7e85da47dffa993803405f7d77f384bebf02bd4037f3dc15c8da7199cae74d75e7c2e81333ad6b622af86fb43f8eaa944f327" },
                { "bn", "edfa0d662bf7aa75dddd4e03f360c5ce63c10533a9f33ebfa48a16904d2385b282d7983d0513729a933be93a3e647676d36670a5d9ddabe5a07630040ad5c340" },
                { "br", "1f1ce983bc88e66dd05b283263b3581517c6898538f8edf33fd380a93ad962e05d44736b98cd6c2eb4275e6ed6aa4aca80adbad8bef3aa7be76112d0113b2984" },
                { "bs", "6163819dda47ecce96c1bebdbe2039213d03a001e27c60064c71c538b021ca5bb0944825e56aaf32eb32a41fa484be31148fc53e656042fb63fd1f5b72cb2c17" },
                { "ca", "22e70dd982421e575936311380e0dd1897cad744050707dd6f701a26d8d2b9e8f8717b247ffdf15a170746d25e5ba539dc406328e91f44790279a97b3eb35c0e" },
                { "cak", "6360d74e0c95cc30782be3a229302517bb7404d4168e9e1ed8bd7eaf4e2663fd1328468a57d29eb48994e330c9fa9dbeeee15e4a23565418c27dd626c618d8be" },
                { "cs", "af666192675392b2e3dccb2f5cbc2b7afe47efd12840bb07adf978028c38bcff5963f11706755888e8a0ac0c3e2a814719b144b7b309fb9375e789e8cc580f2c" },
                { "cy", "cfe749c7246bdcbc3b5d62022e3820ef76c427edc2c448fd6c7206ce08a977ea623e7f89ee45b3d35d7f81c1d3931a930a8fecbba9e9504e0c91481798281c48" },
                { "da", "baababf437b80e503d710ce59c7595db970dd44096720294739e7e0bf32a28272b2bc9b4e2afbead43f2787950b2a6c4bae2326ef5c7e2b960794cd5f2b3abf3" },
                { "de", "eb6585008b5ca713535c596f3471f3a2a9babb2bac0fbf4b5e6bbe52786903dee33f172e16e14e8eecf1dec4892b4d17b17dd156650d795c5d10856cec720a3d" },
                { "dsb", "9cd34de603636bf9e659a8cfbff329a27b30fbeef8bd52ee244688194da7251cc28227021250b546f7730013d942d0b5deb6c672eacdcb05c1c27d9ad777f88c" },
                { "el", "f203f58678b0702cb326b2ff13de3fe05838067f2b429e1642ef57936efed2081b20b1a7e2bf45767bbb9e7f32110c2d72068f8dc53f2cde582b845852126d03" },
                { "en-CA", "5bebc86e026a27ad96caa4b118ab0b61db138cbc3264b2d7b9847bdd7780e7409f1504caeb46396e81639dc5cf17e4840758fdd088c117e5d7cf889a2e269d6f" },
                { "en-GB", "5d6bd75c7bda09be60fea4939bbb6855debe49a2ebd66cedb168c9362cd71e59191d7eca39d4f549a66e063f63ccbd6ec1adba073afe3ea2a0c1e8a494c4889d" },
                { "en-US", "bbd68b23909094dd0bec8f555a41e37446efc0a3a903345883283702bcaddf2ea90de433ad852cacc8e08c467cdb1b33fc8c810b7d750e5a84d2508fb5b60437" },
                { "eo", "9eefde79726490b6966a8407ca70c967905a8f47bdef499a3be11315e7f558619544a77026244dfbe08ec5a8199a9d99098c56f9be913b1076990410a2c2672a" },
                { "es-AR", "4b1b2f503f09824a28b7f49c15b16dfe61217687c642a1f2d3a0fcaaa11f3036ac693f2228d7f767780ff391e8b564230f145a6e895e4c0b574931f86d550e4a" },
                { "es-CL", "ab9725791848f5376c540d0f3f187869ab39ed55e483fc8ed582e9d6d2f195180623e06154c2d30b2bf13d2d25b2a22a7eb89b65cfdf554ded1d28330c51cb53" },
                { "es-ES", "1a3ee37c22d2e98fa9f6c910298f37fe85bdb4d32656b383ce75b1dd540f4093262e62f9e23e9e76dac9065b0a05806087a87251cb0ff1b881f88a1de17d9933" },
                { "es-MX", "f400983f5ca63da32e8923847724a898f631af53f4a2d964d41c0abdb7d324a5aeeb8fe67cd127b2e5311085448108fc8c214af6229e7c76feadb525fb27d238" },
                { "et", "5465976a71900ecc62cfa7ead62f6e935cccf9cba018844ce5ae4e3ce2d2d591c3b70bef1e9306ead3c81865a520736a300cf88a76905fa18fbc2bc12cd1bc9c" },
                { "eu", "8e7b77f21bb59c4cf6b5d36daa8f6a8c0a6f12ee14db7fe2e473564390a93116ab579fd4c9bc01431403ebe032f273924907f3f032e741003baacc56d56d70ef" },
                { "fa", "a9f8a5db0eda591debc360797c4d3ea5dac7975091bdab40c404196659c09529abc21a4fd90cb2ef4fc5bf6f43dd4900189f0ad3dbc8286bb30429ef3aa9e546" },
                { "ff", "4edcfce4dc6bd1d0a1ebf343437a9e5b30690f796207029edadba1b3ffb5ad94f1ad6747b619550027ead52ba1d9aec007a855c5f2cfb2ec246d3e78ac2db6ea" },
                { "fi", "7d6a946eb30e134d26ed53bd983f4a5bf35ee9e2f7aba9fa5ed50e3cf762423a7747ddfa98402980764edec2fc74d42c554cca36cf16310954a3e30ffc144faa" },
                { "fr", "3ee307ca6f3bfc33cbd58c90436a4d4ca0d84e921b82d097ee1e73cbd85791dfc4cd5d65c671304882b55a57d534403a4a4acab3c8a1be6b729b32f3d84b4470" },
                { "fur", "9d62c7e8144b37c5c6dc57e8a07315cd1ac65e79c354a0e3098e68ae768da05d3281b3254aa6bf3261a325be8a86d06f4abd094ad8cc9494def371f745c912d5" },
                { "fy-NL", "3c019146fed8fdbc23b5ed2dca800312c277ad9429f9df4c43add29796e6a48074285059a9d322f27a355bfa4ec60d9170cbbfc81cb7cb7c21a345ac04f38960" },
                { "ga-IE", "1255695cfaa1e8bd9a54de9c5750921d8e19ebb519c74dbb7eed6782fe2bbb7870d2b8eea6e4c28a7a20359d744f911e2d71632ea5a1e27c1cee5670092ca4ac" },
                { "gd", "8de43b38db3ae3d198055712cf8274704b28650113fa5de87ee7e37f93e0e1a5c24c9dbc982e26a42de2d5c401512eb3bcfade9235c82c9a4a08e7ec793bc6bd" },
                { "gl", "8a52a3c96c0fe191b8b3082a72d6f86ce735df22fe3cd5895a2ea621e19e3a704645ab55ba826f1a821dc9d16687a8e7217075554a1fb626ee7aaedad7287e6f" },
                { "gn", "3cf2f8f29234bf8f657de12bc3dc45dc869484a3832a41e557f22b39b1e5b1cbd54af59eeec55e51393636d36dfaf5c3d904b0ea7c069669abc6092a705fab50" },
                { "gu-IN", "d54bdf6b30510b53e7cc87aa803188ee72818d45c7189ec687b7527884e4205dd8d44ccebe8d3cab31bfdd1856db788d86b390c9c6020f60df3199b1b3a99cd2" },
                { "he", "620399b02e1d9c3bd19e7983e3f31006e6b7efca52488d29e454637ebf4999a24f0b094c8c5d1931bb574a58321e9ee8050727f6ee697fca75f97e1d0c6fd377" },
                { "hi-IN", "299b6dd900ed8e680312ac1d915caf3b317aa45191b1e822bbf5558c2e7ce8aeb590d56b992c773512da7aaa4107f864ed78ff0211e2a1d10e57a56afcdfc48d" },
                { "hr", "522ede2ec516dec5c3dd9f5238eb63520909ca0389f3634406b6d8a8159fef3b0b911a9624a4c6768cfaa8a803dd61c9f1bf48ff1a493f56579a652a1390fc46" },
                { "hsb", "5546f799fc75d8da61045e82315ea003aea6fb0542dc2c937b1f653d35384e65544b77257fa1210ce6d3eebcad50a131c2df6c93f917ef6cfce82c0805ab5bee" },
                { "hu", "0ba0c48607aa9457af5cf1144b6c63da019a2f24dd84f47c2a8f60efe1c8625ce058a0c5aa37b6ea8f67700f41593b30bf7b5b030c016e49ad45a0acbb8b0b1e" },
                { "hy-AM", "42a93c0e35bbef5aca0062200c2286318f3abf141b484491589abd3744b0d00d1b7e5ea88c380c1fb9f52dbe22dfc1311b45be33347d542d1fd411bd44c8c83c" },
                { "ia", "6c4c683694ed6a344a1c6d86b37d0e605420e1a70ea6257b652012d4d01c60a38fee4e6bf1697c61e6f3f1ae4be30b47cc09e1406f261a8fd0d3d5d8b4eb4d88" },
                { "id", "9c591d1189bd891ee705dfe375d928ebd0d7124c2e7b573277e5c2fce0326291152076e040d97ade21e804a19fc72b177e0db597bfab317e6de2761c5c997d46" },
                { "is", "949ed023c3dd14e5c2dcf7462b02002a5b2d9648d512979ede1e788641b728e4e9c2007e14b36c2d395c4c7f33088ac6c1930264d8bd68badb5b4c2f28552270" },
                { "it", "87c5ad2ece9b5ec291ec1e9b343675957ca544de2ea261fb05e0abf7b54cbd2af2dcec0584a6c3896a81d1b2f15c2895b720150370ca24e40d2131495dffd2e0" },
                { "ja", "4b15e58564052d128712da78c1c1b6c2caeb8ff263e3e4c498167801fdb393f3cf3f99c70cf7dd59fc6d0d0e0c19395998dea0983463dc348b6b055415ed435f" },
                { "ka", "2ec8ff2d2b7e9a826e40c51e0c4f734cd3080b1abdf47d295633e361bec92ecb3ca0e47b4a88d9aa3352d214efe2d51a45ab52c0c46af5835ec7d1b4e6ebd491" },
                { "kab", "65317f0d90d8ac7298e1d0364c60458288a241d5ec002917f074eb6e35807d6a165a661868f2fe0cb0110bdbda5b7764d4bf79edbc18b4b6d2738ef396bba294" },
                { "kk", "1e9eabf0b055aa0e77ad3199dc9eda83006ec46cbc7dc2ef64dd0d2b508c12efada19581371b7a683b9da5e8da3ccaf38afa6cd6df1e8023f903f3a7bd1e9359" },
                { "km", "c4eb02db47e71cb36c65d7f8853c405fce873ba6e943f5187a22de79d52bea8302376dbbfc952e942d11ba2f491fd8c7af492c4763d201b1850ff802bbb61ddc" },
                { "kn", "78b93b79de84ad3e4794b77c2fb9ab01cf05b3e48284c499b05579e776653b6e662fd9c59568791e55beb756e3c8fcdf1c632d632f528b81f3712fe02a718baa" },
                { "ko", "03060c1c1f1f300ddb91e166d724f24473cdd9c018d3dcd7721c2a4530730411b981444861941a3b41e70e0141d6239d59c0f8f33d707da29bd64fc694fc8c34" },
                { "lij", "f72e6ff351c2d0f428ed4bd2a925414eabfe83b9ec0a192ccd20a10d303a4dafef5f02b8cab0285fcae00d82e1292528d4886a491c07aa8262095c8f82178f5d" },
                { "lt", "7f48cd4833ac687bc6fd40875069b0edfb892645a6d8b3836f08eaf344a2ba3d0765abc6c9259a6212c53b8ac4e3c7507c4fb60b990d93f98125621ec43cd745" },
                { "lv", "817c58d0b1ec4e2d9e723b00861aec311ece0a89f3947c0983aa0622a55f831c4df842bbb1483fb5da354909036658a841dd7da19188409a05fcf3125bee4cc7" },
                { "mk", "4b818840948ffa52eed6893f846f1c323747d4d78a7a3e393bc07619662216b059d1b086de1ca986d8d646a6f44433263432b2d9f4a2cc52b41fd5c9d5f95178" },
                { "mr", "fb5abe6db7e3da2146093065846bfd6caad14c0acdc65d755c76ad4463de90a65f3bdef72fcabbdbb3c570be4bfc7b230d33a72033280a06b9f62622eb19f861" },
                { "ms", "4c086a5927b9ceba0e8126fb235f94427f0b542c442f45a684088f0a9f0de813226380fb1800c34643889cc0db73eb96af9c307dd19756e75d13dc3ec0b37d08" },
                { "my", "25a59a44d500c8a46a4b90127888a38a9aaee66c8641fc3257797d39ce3fbdaf6c0956529fbbe20039c4be0002caaf80ce6ebddcd864b8689275372faf8b5700" },
                { "nb-NO", "e28989587e26807cc32387a02010be648e68b60893706a0968d08288ca41fb532d99793ff989e8c9f5695748466ac422f699261ab3948b9b99a04dcc1ab23bc3" },
                { "ne-NP", "1c178ae25987baa3de893b341691060054b994005f96ef142ff8624b3bb089bf12b3caaedc3f50f8fa8e072580894c210c44b52be08cd4dc7423a94bb988f274" },
                { "nl", "ce1018a23b21ee2bb1d259945dfcf0d8afe36727fd8be44c36cf912bb2d87fb5419b9f4738b71d3e4d0baa6aa91ad62bb291a3a01666a778092706cf06e0d370" },
                { "nn-NO", "34d16e3b9265fd21c571cd4c18b1adaeca8c99fc6cc8d75e283eb34686ffb7a011c5016a176b4bef772650e5d8d5f31b70f65e7e89374bcb920330a2fed5009c" },
                { "oc", "e2cd00dff2584f7cb3bee99f111b62f7dfb49a1221fee267bca7eacc9d3a3214a6c0513a8d3c93b8e86f4f5fd02e734081bb0066aca1f9d9acb11d6b7e7008ed" },
                { "pa-IN", "e141ba9bb996586666d329c71728923449459d910ee142a5586ca344375c4270471cdf57f7d667fc3e1def496c9cc6ae454afabf0cce45bbe0d57c507f99a914" },
                { "pl", "ff227d35f936565662bb2923d7daff264cfd44b62a5bd6e5446de212c3c5f412455986395c723268a896bc0e02bf8d72fdf72089d7581a5eab7b935a79a5f0fa" },
                { "pt-BR", "79d20fa3bd1d396d867e68efb4d90b065ee779f69fe7568069b535aa27a9e3ee78a6f16cbf0639444bb7d1f530fd0e3e2aab7a4c277a3ba5de86a416e00d03b6" },
                { "pt-PT", "6c0a39dc9546f0e16cdf54191a266241b643f3230539441f44fe7eddd5b134cdefc59f499987b79ca64f55fdb1741067b5fb62ae12f6cf6688cc80dc50d356e0" },
                { "rm", "26ef2ee894998a88f975c031db9a2c52830361233f586dbbe69cd7bf59570c63c03a0def69f355b540487a8b09497aefff9379e54c42770954c78c63069eae17" },
                { "ro", "ea34ef6ccb9bb66197bcba59d0a0718e9357b973a67c70a32b84b4cda55a7242f8020cd942d5ba523ed397bda88c1327015a5ecde08201dd6c53205ad801862b" },
                { "ru", "32d3c6be35806d1c5ac29f6f3e7e08b951052d99f92b207a62fbae7ace5c7125d5abb7edfcab3c59f2a725900fa2d3f3fb88847cca8a916a23c3cbfd3c221488" },
                { "sat", "e0e0c421c1f616f6cdf0bb503b7f456004a4106b907bbc988551cba692d7440378477c51f30dc01834706ae6471ae0ace5c20369ea756e3f85eae7250820a5b5" },
                { "sc", "eb59f09b0203e4b21035909840383d2af18d41960bd05c0e664d107222dce3b28df4425f0081e01993b82d4784007083b5c541e76e2c80781e801c330134769b" },
                { "sco", "ed5041f86c1e5bb301476377799273df98a7b7856ed5116d4e26e96cc72293ad4618c58b95524a53cd4776d97f80473b8f13e8911ef7c935d98f17ac5773f890" },
                { "si", "3a46c7969dca1a7d2dd0fe24e02e7871794352024558c8d8664a66f63142ac81aed197c921c003ed54153b6bf1269db25680f7817f9e488110397c675d5774ed" },
                { "sk", "b12b9876fe152bebf6ce445fa17e95366ce2ef3bb10c9fc320db45b4754cdd78ed4f62a949ab42f704036307419970b8916d7f883c8168c7c34bc31a76716f94" },
                { "skr", "b4290ea02f55830cfa81c690d70cf2c31637ca11823016e14751bfa311fa56b84d2c8fccccab4ab1077daa88b18cb2b2379f217b0d98ef1e36d59d6568ef3389" },
                { "sl", "418a1625605f25e089bd03b6eba67f16d927d585d01b5dce7cb3d74280d1d417b27738e918bea4544e5f546ec4ef22b3f808e175824cab6b9946596f01ea971d" },
                { "son", "efa6327106ed0b09af753c3d457758a32f61588ac588fa68c57fd080e05056cc140b7a665ee925f536306aa0882cf1e31acbaede8df9f1344e48ba034374ba33" },
                { "sq", "97f27749365fdebbcb25c401e82243c981435dc614d0b8fed7cd90a90afd5f64d23323c56f5d7580b0d271a7e189137d0477a89a8696cfec07989836d267f29b" },
                { "sr", "cbc7644b1137f9efd80c95d024e365237b354dfb6bd6f06bcb9fb2dc8695a1c6d0c1d5b68a9d5837369d71d6d4b7944500bf373eca5b931947785c58802605a4" },
                { "sv-SE", "3da9022e35ad910f139edd1361a2950a9defd469baeb4d6a187b2b622b239eee560eb0cf15bf25636ca8e669f3b534a5aacc75436f02b84f6a697d61e13ced07" },
                { "szl", "f4a1a745cd887e80fe9bafce3d374b996147fc5fe68a583bfb9169cb6875d0f214de1346d4394a8c8477d049e2b095915870bef33adfb56a33dea218c2678817" },
                { "ta", "731494dc7d4d081616f674236a4b8dfadee3b775997de840c6430f00a08f1b80af56b4128a447eb3906424a22fc4210af7b11fe691e9ac224ec696232ea353de" },
                { "te", "562a7becc8bf96a9f0b143734309f95a2824c0570b41a7a988a946e6ddb43f39b7e71d95160db1d6bd7090b9b374c46533b8f3254d68a4110848f169634709ac" },
                { "tg", "dcf2b9d75f80a8d36c2fe916e95f749b4be244ddcc4dd84cb4e03b0ae4537536c2007f2520085f9b0805de1bdd42b7dab85e78a3358d4326cea0c38fcd5bb773" },
                { "th", "7af1bc19e382a25f56595d0c73a712ba3d88f1a71e6858c7bda9e369f723585f8635040a8a5528e9fdd632f61d954e5f53cb833450f15e3042011b830565190e" },
                { "tl", "e23143f39843e7bce2aef4ad58eee5faacb550ce308f7535478e440f221be28d601e23b21a3168e15e246a563bd97c34b752317d495073d2c0671c2cd0877a7a" },
                { "tr", "48a8286a79b3358264e3322d296530ff6847e762b7d8bf342a5ca39b66bdff375c17f12d6470a1640e7d839634ec2d3f75a94683ded6037de4db3918be08a473" },
                { "trs", "c23aabf422e6eb052b3a8ab3c59db754cb0ac47db3fda565a44d69fea75942608e8b95f7538e91d2a34cd3633080e323dcb70c9bf171a5b9b89bec98378bfba5" },
                { "uk", "d2806a5ea18d439e954f9a828da87dd2590bbb3d696b7ab642ec00dad7c6e298b4e8f36bdd919c335e0da76dc8e9798167ee9784522e5e36b56578aa0e38f60f" },
                { "ur", "c15f99749e8f7d601a94ed81067900de8a65c78b27f9e1893347dea3a946f10d7a18dd82a2b1753ef5a18845e4ba81d67caaed78ed3b082e61104f908675ec05" },
                { "uz", "dfe6614cb6f99c2d227ee15622ffa184875175986d94fb93c5916eddfececa429faf158de3585b46f6bbd2259d299f170c21ddd3bb857393b3e74d46e2461f94" },
                { "vi", "10e5f2950a9ff8ae1ecef3c5d3b69138d020b4cc37041e0597f9a8e7e3acac9b72fc031c88fecf1d18a158d73a70f83aa95e764351a229eee38566519e4405a9" },
                { "xh", "5e0d8561277587bc0a4ce50bec5409ada21442e09c82ed2e058bad7993c8e4b4b536d3a914c48b993a305eb09de5a21c3aa121c63984f10dfa745488e2e29140" },
                { "zh-CN", "d0419147d92411e2e1bdfd7e58722a3db696f539cb1fabf9f72d2e242534c7abd60bd1af83ce2f9a3be0c28612e8107a7155fd20473acbaa08feb222ce355ece" },
                { "zh-TW", "6b5faf1c4ec3ba986ef4ad6c3607e01049042be9a06ca275fd007ba9455c08a604b2d86638d5dba38a61f726e08a09699e21d8cf7c0f8e436fb56030b9ce8b0a" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/131.0b3/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "f4706f890d908c280f87c21ce8b9d0a0b829817ebd5cf96d4877f635d7511437808ef1913164746469fabbfda41df55d6668ca9a7335a57514c5339c0c520e6a" },
                { "af", "43849cf41469a24fe77e7deaa1c7d32f3d10511189bcadcfe789fcd2897af208be419c33fa88f5c8f8371ea5c9853f69945ce6eb3441d27b81b86638fda9bfef" },
                { "an", "9f94a4d63c7378a6c13e9efaae227b02f81a013cbd6658c3775679f0c83c996aa9cf89c3c8efe59c5c9e388e8c11b4a14aafa471bb187b1ebce75f9c21576066" },
                { "ar", "9c34bd331eae5e84a6d7767a6651f27bd4bb026cdf563b6474edfa9bde6ba548ffb0a364bf0127d43062e0fbacc029f02f110e4a69c69ebc738e9fe3b86b615c" },
                { "ast", "021473f3572d4a5f716a9b11c1e7d798615e39ea0a132cf34f42b4d7f6c9824147280be57045f5ee7ef2f033b855cd7cadc3d21b56face306c29e6f0f0fd6cee" },
                { "az", "6996621252d60edc0a3f1057e7bf36b12ca4618a05903b979d0a4f2a92785cf5b6010fbc7b8dc9e916aeace7fe71e90e072da6237a85c709aaffbcb120c147b0" },
                { "be", "9844075ce2c6b47fe26638c8fee5e674ae85f2c58a8447460a4b4af8eb6187eb486967e154f19505533c3fd1883d04b41491d58a5cc3113ddaaf6fd5762b0bc5" },
                { "bg", "36ba5c5afe671b4cb91ca7672fa95a0017902e41a07c5ab807397d27a4ea06307f2473d1cb7729bc41841d82219646846282b31093a2127f0e31b60daa3f6818" },
                { "bn", "138825592468d79acdad48d96e0b6f1e801e9c69244466012f2f315a2ad77e079a83827c81100f9376c6565484f47ffe6cf868f716f293e50381c6b3bf736da5" },
                { "br", "4056421651b079edd9a531b7896f58745e538519bfb8198d3a9517ab0843055a2352b193b6df88ea7b2e0cbec73e9a78a75d3ba9aab265ad375ec4447c931d9e" },
                { "bs", "6798b4b7983cbeaddac1744fb0b095d79cdaf81cbd8978a2eddb72f7b93d5dd8512a2251b09a626a798d5a109803c281901c95b662488eabc13e17ec024b90e1" },
                { "ca", "55e6ab2633f34f946b08d0fbc89ce4a0110ffc74763f9dcf8a4092e78cc18602774c619e8fb81c420afc4bbaa74d841527f903c348f62cb8d9bcbb1e739d20f5" },
                { "cak", "fadcd7a4ad7056db4f0ff5c0f86ae9cb90a76b9b01f4a92f13563cb8db838901b2a028f2f42a0d0af762aafeb1f68985ed08ccfb7b47480491bb303f315634db" },
                { "cs", "b5d665778f04ed490202717094e45b2b4298092b897b3304285e1a42d8a1b85ee58c9c0dc1dc13b30500de8ebad565280bd4e074fd1b773fe8c3f204c71c21a5" },
                { "cy", "a820bbdef47283e351645b3936f66927f72b4d43b14225ece0b9acfd0dac45eff974e48d514dc3a20593b35669666fd1499a7b3dfd6a6094aecec502c3239800" },
                { "da", "9d80d82042c5c9c8ead24b17619ba81908f81c1b34c4fff44c39328897915a363d0e8cc54ac138608f745d3a3bb12f88975b91f1e3f5828766df847c217614b5" },
                { "de", "742f3a9d477609c4b9fc2795618f286e3f0847a438ecb79dafaee10844ae1d9cd198ec98ebe0eb8ef4ac1d3887413e8889c31ab5c8d98da6d12714a037be3370" },
                { "dsb", "9e092fe4438759f06a75802bd61e3f0db39aafd772f9b7f9f2aff030aae3dd09a4e1ffc1e303918b765614a73784f1275d0f19e22e5310f9ad61721c90055304" },
                { "el", "49507f9202513f713dba33a3356e579784d2fc98a20620c642afb0d9c8cf8f561800e570fe0244a1a8d7191d49699c00d4a742d0fba029cf605458b50ac2f0d1" },
                { "en-CA", "1c0232060f46fea93f72eca4f994330d0839f30132ac8e3d0e242c8d18ca90b7d9c3dd2f31c2cf0ca8dcb2575d8a37817a5c6ff76c43e242ac1c9fb24032e117" },
                { "en-GB", "3292eadbb1b9e159a2f7f3e3bea5c3775f9eb1ba1a1343be7779dd1129a7eac5f1cfc961ff78d92abbefc7563ca4aa128e9344028c0744be73f96560d75d4a01" },
                { "en-US", "6fa92bf31cac1af3357226eecae59c610a9d9733a099a73bdae1ac80a154f7ac1edc49a68785849e6488b95bd2713174794e153013c592458bae595b23d17a70" },
                { "eo", "0e06270b299063b720eb47ba8a7366ebbce3c02acdf62e276c2a54918c72547597459e5b7da31575e4aa4d93ad41bdebe10323ddc3585b850151ade4e2eb52a4" },
                { "es-AR", "930bd9771fe200bde09f30e47974aa005fe446aaa0988d60cab48d9050f80bea8bdf2aaa4dde0c6d2bb413ddcccd0614d01b5b6d4a71fdafcf8f588136de564a" },
                { "es-CL", "b4275ce27e94a1389f141bbae5f4939396be80db806d38dcc7f9edad94d6be3147c236a8e0c4b38a3e79f027b6d72d3702a0fd29133f3429b6262c5fbf720adb" },
                { "es-ES", "a4b5ef2ff25e3d12f6aa04c41aad5da10238ae29c925e55f5c753b5a146451977948b068d6b2a2bf7f1943a964d23a93d1fabf068488ef277396a2406dade1d9" },
                { "es-MX", "f56834379b3ee996013d0e2bef2c5b43765ec6e47579a744930d60ca6a6ce60107cfc8a3c6b23332285d71d97095308f653b45ff26728e6a8c6ca95298cffbf2" },
                { "et", "fc17951ac9659bc83f64784481f517fde0f58a759616920a4bff5be8c35f3e4d5ad755dbf985ae91383cb184945c23c084b86b915b87321f5fc604e782bc0b61" },
                { "eu", "e59f9b96f467a3ac2b060304e57bc3f88be40db82344520370c3fee4efcb2c86b82193c6d77f102640d031977f5339b74d9bdc864806bc3e797286c6151a97c7" },
                { "fa", "a82cf37cdabf861fbab513530f72a26de91ac5a2159dd6643dca9c6b52d46f5a29958dc84d3c4cc5e9617f1b2f26ced1bc50578a232187476e68c2d48dcba061" },
                { "ff", "45f1f3786474b2e14b70c24d382bbf4e8b10754af5c968015d667345b635d686fe37cdbb0483c2ab31fb1c966233c5006e2be4502f47f0c4b54df6777e149cb4" },
                { "fi", "8f8158f29f5b98a9088c4d74eaed12d5d42a5345f8a5527a2f822a7ed5d85ba52fec6b0f6f34b8720b1399f239d4fc0f6857a7899e612132320df097ece9152d" },
                { "fr", "e0bca16d8ed439df119ea687e77d8d737bcaf4f2713c2eaf450c8ce40fda58a87a4e023190cd682dcfac71ff9c2d97d18043c9ab409a4030a00cedd77ad0840c" },
                { "fur", "ba7936f87a1c66d77927777f5edf7963daf8c242b16987ca07bfd9aa60b7d56479ac83a326a96608de8d3733cb09873e317c1a121e3d743e1a06e1f13c20637e" },
                { "fy-NL", "f36b1f8abbddcde082415c72995774ea026fe16572549e2dfdaf377bae6cb24eba77c4f7b5ea7a148bfae01ec978d6e0688c30a0d2a64ccee73ffcf117978021" },
                { "ga-IE", "23b26ff8f0debf598c60167f20b7493c94e160ad39728584f84124544e86c748175164d2108c3ea5339d5867da5d1793b964e73d18a5fd7c8ffdce5d0f27689f" },
                { "gd", "eca7f21995e31b1e7ffaead8a4da3c65c91203f1a92c9ec8f1c3036d86c78f32282f94e3f48728912a209af0ea5cb776bc0042866e8a9f4a274755a9090703d6" },
                { "gl", "7a1446c8a231330155dc8fa54046f3c59497add44dc448b9afcbaccc3f48e94c1aea1b251afa603d848324075d025f0e9621adf113bae7e28a91d751196c68ef" },
                { "gn", "0493e42e4a3516bf3a39eae2360df3091a4fe987e576232c6744c40a9495c3b64bb91087b532373f95d0758b2319f24800d2afa0cd2752d33e99372f54b5bd7d" },
                { "gu-IN", "c1b2be5a34be3067a7c8617aaf4543910bc1b994a79f23c46c2b72fe49953417e4c6beed5615bde4178eed3ce8b2d7f1f001cdc06acbfb552a41e21e69d1d667" },
                { "he", "3fcff175fc564c7e36a5e395889673a62cb0345851ccfa0b6e88f886d66d01436a59386a0f96a8f13b1817385e36a61bd2dfe1f3bb1daec58a51a03f301fee29" },
                { "hi-IN", "bcc32f5b53903afca2bc6321b768e9aee7c35d1ad7a7ccd1e719978058cf42f8066451bc53f13182cc6a7fe6709097d6e20c46694850a99ed3546b4607d4a254" },
                { "hr", "be09a686d64f608a04f54e81468427025065097f8b8c025fc2f784159a5489fc2726ab5b5ca8906e63e596f7cabd7093e528509d539bf6ec19f83ec7ecada467" },
                { "hsb", "a5a98e970671579fae9d5b2970f916655082f18bb1ebd05d1ce8f07ae00caf47dfb9d54f34e62cb986cb61ab2b2c1b2e0d567acccde7ec69e491366e42ca5f7c" },
                { "hu", "abea054e56d8083d1ae12d099ed02c08fe2f2a762d2c57d84625002b7a919a2f930b1e0ba07dff5b7ee3c50393bd7f90132b021294c93464f1e08ae3e5a3a47e" },
                { "hy-AM", "6da124264d02cf33bd1dbe2c158c35de75c763b101264df06706ec9305f1bb44bc586166e7e943fe8bca3558c56e5f711def62f326bac84a0df3b8132216c3df" },
                { "ia", "bec3918cf315029a5bdc3179fe8255ae0ba7fe438c4e87d4c25e7565d45bb32eb9e8c246bc072c47c05e3835fe3eeefcf32712c101de1286b26d4a55aa372166" },
                { "id", "2c6019ac1d7c9ee07c96626f6fd7205a55bf440ce77a74f9e6787662a094cb5ad607c5560eaba5b3ad8e11c74bbb22813c404afe682a0c9d89203b00c16aa0a8" },
                { "is", "4ec41f1448c7e6f63e74f6ac2eca5e55addb68adbdebd5b4b445ea778d2ad25922c3d7faefbdcbdc121473f29c11d688dcb84c0b2aa1de1584cff7907b8938af" },
                { "it", "bb1dd740282ac3f5df76b0e698c012d0bef0078b69731f358224283829bf5cae4b9d6577943861515001048a037ddd76a60d9568e8d1e9609f60f9bfefd10d3d" },
                { "ja", "a07fb3ab347edd2f4ab03657859acf11e03dbeb2de17c2bd1aea3dd66d6b4c9d1f83e72e3257aed86a0e7624fae04a19dbf2d74ba16f7e1ef4eb3764c33975dc" },
                { "ka", "8b1c0d19323bbeedc83086abab0238edfc0369eac9046d4a3cfe33d34e2fadf7909c904d7f1355fcd68a278fd17468ded0482482164dc327197c29affd9598b4" },
                { "kab", "ea2b987fab9faa4b477035e8ded5bb9147e6cc824207c92630ea8a13adc6fc594d2238bfc0d3d28d7cf33dc9a505838bb885b1be76350f46840dc1ce35e9650a" },
                { "kk", "23de69c87170f03a097e79fccc76dbfbb2293b2d83c72a6ed4d89c172a38f1fc6977594e0f6d2848947cc769304b8843b0b97f25285a3ce3fd3961c66f663ae4" },
                { "km", "96fea4e5bd308e2506abe01518abc50c78544ce5bfaac99d109fa9e8abedaa3501f856aa5ddd9bfcbf7857acf97b785e045c3bcfcbd8a3952f83676bfeb85c2b" },
                { "kn", "13906dee51e67e5e3022113230c3c94ef9474f6e5e6f8ecb4eb4a91708f833f73cf7074a8c13101d3167f79516e1d7a7ca384ae8a8c125012dfe1880a09f4d93" },
                { "ko", "be82ac069760594bea8f8167f82e7e4ec39ab48b180f109e5d703c4155f347f4f4a04238c42e3192240a23ae40d90c3c9f563186de8f09a2eec93c5c51cfed0d" },
                { "lij", "52ce189d9e03fa2f12fd9d1b3516c0e99faa9a71ee6ac59c3ebdc6b17cb00b13497740a3be4a53a5d1b3eb383c2ea55dfe0594fb1474aa60202dfd314bc94f19" },
                { "lt", "73857d3d508f04c8cc0739395666f972dbada38cc89aa8fe3eb9315527fd2110cd4b250a14bbbfe42804277beea5f32adbefa04ca7227d57902a099869d41384" },
                { "lv", "481e5137a6460c49139c1795322cba29953630180b1c15821958b23f8dbc89820f2a9234caa8845984028b0de179dc3afb4c55edb1c220346f0bb056fa7644e7" },
                { "mk", "21a7ab212cef1f38bd0db8be5ce109ad5db734005ff909f47166ede787fc653de98cf969d6258afcf938658958aa2e95232d9722462b48ec955af22531c7e4e6" },
                { "mr", "866e755e3aab55f8e3a7f8af7a06e8fc8eb30fbea7906ac3c48acd864f91bfcea7377544fb47d6335c01fe83f322b3a28c8bfbadd6b9588734f28e86f26f09d1" },
                { "ms", "53786b248d70689928d71e5f4ec6b7e772080051e774f138de906d08467efadb0be5d258cd0a0068ae5c5eb5ce79ce23a641dcbda82dc59593f146aaaeb27a42" },
                { "my", "c95f2c70c84db713f4a93c8d11ec5aff50011f0055ae9e3b11215ca65861f88dcd442415569db9db349a20ce7579b0045ce79cbc3b7c4cbb1acdc5d8590a620b" },
                { "nb-NO", "8962d1b861ddeb6f23768ea446058f8176e0f59f67e8b2a4b7e5c0a97f65157f779c4c90ec927956b23f1fb4b3664edc393cea79834639665b75dd23ef51b0c4" },
                { "ne-NP", "b13d927b182ed14283b3943007da7f2395d8c3482911463e44c8a63d8d3257e5f2113571fa4ab2f87317e7e48fd006482d4392038f53cc5aaee41e25747f48e3" },
                { "nl", "5f046d513364771e3d247364f84e867ab51dc52a2a06a51841929dfb36f3ae001768ee4959e56c08ff6c249d62de3a7758d5aa17e63b6aab97448a5cc016c933" },
                { "nn-NO", "44402d94524026cf5e78123933aaa241d4b6a51b232e6870c0e73c6873e02deeea1508441d919b725569f45a7ecc157b5384302e74584326c1007698a3bc379a" },
                { "oc", "e21d494f4566fddef59877bda72ea0480c93e7d6baeb69434def134f28f2e7d35c0cfb0c52ecafe7c31adc47e82923098bf6818674c270ad61f2cd8ae2c2a69f" },
                { "pa-IN", "6050eb0e94bab797c684793f75a5fc1d5c2bef27335bcaa694aef368e5a2aff455e268c6548b543a8ecca5e6bee044ca2372752c2b410a31da92a4d94db9e79d" },
                { "pl", "e88a02692c1e9c2b15c74f01d79200b4337e28e8b0b39c5e7ecd264d461aa3e226d38e9dbc281a322510d8c3a0941e30cac3ecb1c350adf1ed7b2b258b92b52a" },
                { "pt-BR", "aeb292eb471974044b747acb61393d164b7d803b20834e88fae3949ba20580718f3484548f99194af2adb95d5cd4557ecbd2ec655fd49074470ca7726c29565b" },
                { "pt-PT", "bbb02eccaab5af827e98ed623ca62c83153690b147f0451f958d7ff37e8d7edf14f8bf8401ae4b582eccdeef3e5e5f55cb2e6f9e11a83a448b3dfa8ad2a2b481" },
                { "rm", "d020bf2c9428c35a0e371d1368ad2f3f9e6d7346f837a220be6244a35e8986d2a4d02edce4a376315b912f2e6097eb5fbe6c78e73b5099813c35c6a374b68aad" },
                { "ro", "d159a40ec496380cf333ce1b4bec143c5ac72a099653e2b4a012d86fdab10f68863c9af62aa985d28b6acab6ed2ad9b5d523411bb13a52c851982c7df025d29b" },
                { "ru", "5ae43dabf19cc85112258b627f644b3b66e3cc5d40ebbf864c3a80587a9fc453eccb045f8792086e1f05ee690e6baa722114968760cb08a6860471324b004d52" },
                { "sat", "56ab7d8d2bf1bdc5f5cb0c471d7d804761d07016a8100aa0c3219bfc70e879d5958b555068ae8988663d3c8e65c717a97f4b93dcd98321b7999e179c172f7376" },
                { "sc", "e5ee93df8c8f34a227efb0843de3c9e531ea25b3ef3fa40c8b25fc7a63d94ef1796659102b22b9258c5a0917b086814d34223705cbbcf3b42624fdc2459427f8" },
                { "sco", "33fcfafcd85b3933da6753c529896a0cda87b21d10224c7b803b7772b1f897d5da42804eb28409dc9f8ceadfb1eb2b15385676f5215c376af6c3584f084cfd04" },
                { "si", "331103d6188181f50938df639af9c937e31684cd8d24cd906b38b33a7db27dfef9a8f9c1b2e82e4aa9b762e2b595d5ff1b008c52a2801e78d1ebd40b83ab4919" },
                { "sk", "8173586b197199e8e395a29034dc95d07efd620f98ab5b9a00977d6d4a16339333fd210594c86c6ad81c85701152c8ccff980247339fb32f7abc188749f4e306" },
                { "skr", "268373b763ab509bfa1c5a032d745954c0f40b3279f3c7e97ab7f9b83e23e92e8e394fe525c781f37898c93ea1f83c4bdb8552b0a1f22738adbd699fdd09710f" },
                { "sl", "d18089c59c57efa8b7967a9854126d059e79105938205c985d866e45efd517a67f4ed3c801896e6529d5ad5ed4d10d0dc2d4baaf271c189e5cdba979ab366d65" },
                { "son", "56a876032fc0cfbe0ff317ac52d04f8a5f3729cac89bfbe672c5617c1e991a068a962d8f5e509e53692217fd3848ccda3578d582c2a95e51a8a2e3ac13fa7c21" },
                { "sq", "c01362fff7b4ed18a44a4743ff72214efd906efd524c1b6bd70ea8bd7cc7b7d05d8a8b2bf3d1758d04cefdcabe57c6c81a2fe1f40e3ca5aa1375c297f7180d47" },
                { "sr", "85d905f25fd70f7e0b656802a7696125bc9686cdfd30a7c406ce36d7c827f42146a86e9436b10431dd0879192b561cb3f022d30998402631c365d770c63a12dc" },
                { "sv-SE", "d75266d05171895719b57ec37365daf0457da67f62bdbb55850d9c3b0ce7729fde1ff7a608851801824ee0db6397df0380abc715b4072fa953568ffb08730cda" },
                { "szl", "84a612d4142b2be70f056f5c4a224cce65cce096346810028e5e13b2045d978f56ca3c775ba0816bd8b12449f4a64180e3760b815b3896fcaac5693e1319db46" },
                { "ta", "ee61c7c3c6b016310c86ab585a2dfff830cca74f956c9e801318ef2bb7afe013de0aabfc2c9ce32918486ed842dae8125662c6db3fa92b2fa4161b5f9dc99afa" },
                { "te", "d43f57903f78b6c83b755a303142d438c49947e30ac431c8f111f38e7641ff3740af73897ede059d3c53c063f90f20b92e68e276a60489bc07e3dd66a90a0851" },
                { "tg", "e03b0b75587fdc055bc07a1d40ba5823a7595790686bc9d8b336386047bc70f90f7d2c10d00084718838559875f9f248cf2eb7709d783b2e7a9a3a0bf9f2de5e" },
                { "th", "69237653ff671cfe35a2571b540993e659f77e9196a4e1ea0ce31029433dc967a0d3a1088ba42dc7f2a4d0e12aced9cd75bc030753bf84e68bff00a9053a3dd0" },
                { "tl", "e1db2bf3e51ac5f63f794de1a7e8faeb639ac3095473be09bb2df9398e0d660bb77e33dd24e3d2fa1670592f273a5841ccb33ec5e37f571b39518fd2d5058d9c" },
                { "tr", "22aa59d2d0ce8bd888d9977a0d09532b3307aafcff47237d2be0802b1ad1b3d3b6b69fd9787df907ba8d6931fe7a59f529bb89bb4656d7fb8b62bbe632ce14d5" },
                { "trs", "af9b1e42ef3a88a432ac2460e21be45da3983821e19f8fac403137e90786f8fa35053f5d2d1bc15940efaa8f12bc7d55d888c382a1c21a146378c3094edbabb6" },
                { "uk", "a0f2f0fb1d54923c53432d155bc1041fb9995a406dc352024dfec978b7e2c051ce7b10833549970fc181cc12844629ad0919ae098232a60a615fe38667c22198" },
                { "ur", "c0dd1c8d7f3d97278473d847628736b914cd2351040861943369495daa768500ecc9d6853872fe3624936e5673ab805580e3c12b68810971634c61c651dab4b4" },
                { "uz", "45aaedb24fbb4778eea021fd19d2146a91f402583f1e2696589fdae0c1d4c5a788dcfbadfddcc387bed8058c87f775bd0297b57e5210cd6f6b3d7c086bc17c81" },
                { "vi", "d2e50c53f889e86f1ced377dfd039d9292ffde35e0d3fb1445ddc4208e594cea31197cea4590dd996e81f7b86163044c4271604430bea133e20546a3d249f308" },
                { "xh", "51d3646b39af6b41f737c8eba798922063d895e69a4dec362783d098f9d625b0d7f5e7e6dd8820890185921472a2de9c830a73f2bddc4a3ba816075c4e3827cc" },
                { "zh-CN", "258faa4ce47e68cc6bee91f06cf87394ad96172be5210ba7585eb2f82acd06817fa83ba7fe07ab61152793d9efa229fbfa02927d6e15bce987fb8300aa8c8ab0" },
                { "zh-TW", "cd96a694c9a139efed807763ad77d5d3ff8ef5f1280e71eb4da244ee86f4da641323172449ef246fc8ca4ee8536317f17453e6dd9820ccc3c9feab8570326dd5" }
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

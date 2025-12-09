/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022, 2023, 2024, 2025  Dirk Stolle

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
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using updater.data;
using updater.versions;

namespace updater.software
{
    /// <summary>
    /// Firefox Extended Support Release
    /// </summary>
    public class FirefoxESR : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for FirefoxESR class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxESR).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// currently known newest version
        /// </summary>
        private const string knownVersion = "140.6.0";


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox ESR software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public FirefoxESR(string langCode, bool autoGetNewer)
            : base(autoGetNewer)
        {
            if (string.IsNullOrWhiteSpace(langCode))
            {
                logger.Error("The language code must not be null, empty or whitespace!");
                throw new ArgumentNullException(nameof(langCode), "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var d32 = knownChecksums32Bit();
            var d64 = knownChecksums64Bit();
            if (!d32.TryGetValue(languageCode, out checksum32Bit) || !d64.TryGetValue(languageCode, out checksum64Bit))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/140.6.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "2ef10f00f9f72e75bc41354adf249a7c5128f5c2a47b5bd04f45cebc2b089a8773154116e28e61bd13d7ace53bf79fe7ad4805e6087cdc6f9124dd629e87c479" },
                { "af", "dcb1213eea58ca06ee79d4890bf1b1ee655347e1dc3f65c21a435a81f4e3e9ddae6c93bb2d6bb5ccd4a5b58a033de4350e1cf979d6b23c8f767a15cfee872211" },
                { "an", "9112cc104bbd50e1ac81c260d639f8be56d815ccc453dd9984f6cb79e24502e1e6d1c299898e8a2d5a737fb49173b0daf02fdd489e7ea51dbabdeca994b8e42e" },
                { "ar", "3302c2ac7947c2d689a8f5c95747678b5ca24fee213089d767421312bd7d905ca2395e7c9b38652dd06a7cd9526b462e0eea9e7ea5444cf71adf51bb86f2f768" },
                { "ast", "370f47dcd2a58d9ac2961ad0157ded2df915c91d2a22a8ad16f2b270a873bdcfdf2f57223eff7f164dacd4ab00bbc5662ff1b1f0e14c1c663e0c4ded1e568ea6" },
                { "az", "8c6bb5434eedcb0be0c4fcfc6a3360dc6f5c9fd1b1dde69c7ca6f664a371588905b7c85c3de9e6ee2e56379c993191fb388c381527130f303f4ff966b7657566" },
                { "be", "a98c77dba52d5c9ef6ea3fefee7b0f6b32f37dc606fd9854674aa1e86e27ec9b3741cc3b260ef361019f581778618abb11061557421a25620b4cb464573d3f52" },
                { "bg", "89b8fe05c58ac1321d826a1cdbeb9afd07281705e9bb6deec563db196e54631b8641f0531810921951fbceaf743d3d8620fa29d0d55e0b46ffe7ef69b8abe9e3" },
                { "bn", "28fe120e789835783783c6252534a7d0ad1a3cc058ec98cac2f304d2e9a8815908574c8ac2178e37a95d58a0ecbd2a9967546603512599e4db51085058608d9d" },
                { "br", "059bf7f1f5e682f7a9fc839bdc2cb613ef6e7b0c5c0ee3f2855ee5f9e45127bba498919fbf10dc84916ce51af0898796806c5974b182088e53c21b359bfc4e5c" },
                { "bs", "07082c5a2800abbe9a7592a9884269b9652256a5edf0e687cd6f443d0e2d9dc4b498b1a1baf57b145ca85abeb42c825be9565ca810cc9b5d08b7386544403587" },
                { "ca", "64227feaa1ffecd0c1acf24f3d2e4bb2efe1ff7ff0fd44443d55046584f3d1112eac6c1d959c89f735d2ad94e71550c7a392cda3e74ba0ecb1cd6342c0f61b56" },
                { "cak", "0d8b9b0ebc1b3722ed58d848638eb306e9a235892ab5969b96723e19acd7dfa1199f4234b86cad1b6eeabb63d54168a536d6bbcea8573c48c1c0000864ad6fe6" },
                { "cs", "3073288b236763d9add5916f42a5f256939fe454bf0697a8ff8555577c2f180da508e83baa593373e03cf4f4155afca18bb96db7bbe2558dd201d79223b93a3f" },
                { "cy", "dcc40bbd453134bb0968b35390681a9f3086d21604b7f791183a0f27f012b0dde5fab87f320accb8c59b8c8768978eb58f1e20ac6b483432ed6176d687092c6c" },
                { "da", "b2b05b83c102f7a9af71230827eddfcd1b72364375918de07ebb52a7bbf7739e9917928e30994659281a869ce1a6f59986bf160f736e055f3e6717eb0cee526d" },
                { "de", "6360984a11bb173796465de2b3ef4de4ee165c456ab20a713a620a7bfcd83731e92db4570733d6a8c03595802ded8bbf419c09b18d347e1a34f08cc6f47aa0b1" },
                { "dsb", "e823905131accf012856e8efe52676d6b21550746fdf81d2ba130641b6777b94e7053ca3fae53ae40584ceea94b429c4577d11cebf3216da35d1a91423819537" },
                { "el", "2cf7a2c7483916c7676b4d46698494895e50bac2ca00e00a46c40971368b035517d287f786de50734887204e585d1d1c468f184760c56147fe78dfb8012ee3c5" },
                { "en-CA", "23a0e4761f0108b6f8dd524c285a638ced270778a18445f1d14d2df5398b3b275b8674edde5b376e3f4ad7c36ff0f357bc4ca85f9ac931073065936a9d344726" },
                { "en-GB", "53a7612cf6932d15afea316faf579af7e07e88fd8addd70e2dad49b910dae01b2f1db18fb5844c05e46acdfe6f2043e5832607573dfd60995a13abddc4f39532" },
                { "en-US", "b6e7a7f7ea91f33700ebf077e94d47d79d8c558e80d5bda79f41b03f775286408c4216ba2686a221b36d792251363e7423c550f0e48d287032044d023421a48c" },
                { "eo", "4f64eb0fde5a25980bfe32b8ec572ec3327d43ae90bcf661382f8253277e0bf3f19c4fda8027a0b34ec29929c746bf63ed531454e58b600390c68d9672468d9a" },
                { "es-AR", "41fe775a3ab72d8d99d7f907f1455e17ed63a573595380d0a87aeb0b1f02f09509f601dadbec3c31b60c120820d034fef25d167db7c4088a8d5f50fd703d55d7" },
                { "es-CL", "d1e7a76678091df9c10acfbd86e2fda22196dba408be68b2e9567d584f0e2fb96c01cf495f7f8c5a6c5b8f547d8fc05b3f5a69906e0122cc47e5b0db39942149" },
                { "es-ES", "4a6c794bf72826fe92e636a9ba4fd5e16152d8cd3f1b1041200288d5a77b8f2a925ad6a0bd3930d2450f8517ba6c77ed892d2754c15f9ef90c3dd22d5a234ee5" },
                { "es-MX", "f91f6a9863cca1ce3e42929689297d371e80c23aef87771011912626fa3ab2bdd70a486b041c14adc03d713bacf12138f55041507dff6e53b83d3ff590d27cdb" },
                { "et", "14e8641b98ab8bba92ebb95295cc1dcb5c663bdc2c3053780cc2d14ef98217dd6261abd9a61fe177c12cded17c59df461f74a9dc1b5eb7983d474b679e949fa3" },
                { "eu", "0c2342dfbff9fafe117b84b0485e8868b1279983e8ad95be36a56986cc2e22c35ee609e81aa36b2a53558785df530c7a37964beb713b381ef81e2d72c7bce8e1" },
                { "fa", "61a442dcf3f5a274ea3568e17d0a8ff0f82620c5185cb18aed502c99762d0973fee62044861507d834cd85e5d3486be66978f43b9aecf725b09a81df1f2ae10d" },
                { "ff", "0e402604ecf12e38931acbb770b6997260c495369992785514377f62d07fa7f4c75e22f63f46480b1fc222457b60733583f994a167e003d94a775439e72dc6c7" },
                { "fi", "828767998f6bb85b750a3746deb13d60d1b41daf4fe99f059331dd0e7f0d0610bfb41444c4a5159a2546cf42c2491b6069049cb59afaec5558c8cb9564eef106" },
                { "fr", "a46fc1b9750303aa4cc08d4c30a5780761a6aba9dee05c8137d11fed8e3787f578ec0bc5bbaddc401bb501771c8814f4e555aa5445c630ad92c34961eeb718aa" },
                { "fur", "720100d668247fff67ed65f2f100200a0f934813608222ba02cddac7e201fa15356fc9014e81ebfb8dfd258c75f915c1d32805b8164c87a4bfabeee62a3edd90" },
                { "fy-NL", "7e3add278178faab798ad1fb18750bfebd293286d42ab0c88783e65561bf12b619bdca3c03ca54e7cb8e14fd28bcc528785a074b4b2876ff24ea4d272121a212" },
                { "ga-IE", "4cdce5bdd14469218d82e1f5279d9c0b69005db047cdd02143037a19fdc5ec117b93343f1553d7930494a668761702e958e6f269b0a0fbe7d9111804b0a888d2" },
                { "gd", "31530686176de300f6e8f1c7a1fff45605908aad3019252644c32e2ee647b83ba97cf0854afa60f5ba67bf8b906b79df43fbdadb5ecfa8b5ff8e696ac550ce54" },
                { "gl", "484eea75c9995c8d300972f3ea396b7d633f57b70c953cc300d6e1548059497a087e2eb310a723a1af83faaff66346197a14a9f49eb38996292a88a668493793" },
                { "gn", "57947472047606b03e480a2ba31b3046816564770f21f989eafec96d6f907479e6508a4819485fd670e9f2b1422ce5f75af4bbdd803628c948e16353f47fb2da" },
                { "gu-IN", "24fe68d490fc30d1787306bb0d10e5fe3fb4737491b7bb5a21ae64c8ec1b94bb3323def9fa904fc770f2c5653201782b59f1904d881de324719039e2d1151631" },
                { "he", "e227ea4fd76aa1b18044d3768d30e105a718f02d73e211ad8db844579e67fe7ed29ee45c723454d6091e6785086dc0a8635519cffce28ffb66566d15ddc3cbff" },
                { "hi-IN", "4d20169651b859d5f7a67218b8a0a0b5a9a309245540589c672d77f7f672418cadf1f4eecb78da7821874c921043019892dcc8ac850050a6596a60699b42abb6" },
                { "hr", "2d2889262156bda905333160e49735614cb7943dcebfe3bf8cd72b52e088407a9fdb5feed1a018a0a33a7e71c5005f8165cc8f1013c1cc77af4efb5956dd4be6" },
                { "hsb", "c2538721753c0a77e5c5cbba89f1230eec5859be9c3353b43e595e81c14fbb22e32478a64737f3f491258ef7029c0551e802139a30869fc9370fa83a22570c5a" },
                { "hu", "3fccd89a5acd70df8a914ccafab59414ca3426a7fa6779740e7a3cc60258c04133d5c7bb5ff82c2b40c335aaa48badfc5f6c9c0cb9b6d9b90ee2331fc97c413d" },
                { "hy-AM", "660a9c54a14d9b87f3eff83fa13f9345f2f8f92513bda8d08c4ec79cd7b1685aa64d9bcea6371b0330a44c8e7f9234fdc31905990fb33a205bfc1b079d337ff3" },
                { "ia", "101b1c72bb411e68632337b902fc022d6918cd322589a535b5c0f39f54373ceea98b3f62b5dd35e046138c237cc949a8d4becb61f6325cafd3fbf1d00585ff43" },
                { "id", "3a0c610b2a22092d2091eb0e85654741280fa025733e8521d9f58cb27f38ea509102765046227a1f24f488c8fed0e25b59a77a0251c6cafefdb037f3f72cbff9" },
                { "is", "b8c3fa6604f4dd25d402f422d95ecb516c663c521ecb8c3f7af47bdc44f56e6d3b45a2ca24be1e45e4b332ae520c08cdfdae973fc7eedf9cd2b1a770349a701a" },
                { "it", "494cd8db01e9c8a2814a1f176f452dc44f87167a2f9024b4f414e8b9b7a3a83b02851067539faf72a8a2e8b77efad7d9a41d60976e01ee7ea6a39a46d0d30a53" },
                { "ja", "ae42229d27a10b962c602e4045bc41b0efb287a2fb431de9245bf8371ea9b251abf56445c7e4426caa8b81d092720b2ead4d2dca678c4b65239a17fb3adec552" },
                { "ka", "3b422cfcf319a648b39dbf8047233c57e1a8410ee801792889adb93d436372bbba7a01fb4be4412791d459268e022425cc1e8ab22a355ae8deeee0aa19f9c9c3" },
                { "kab", "9221a01817f9f2c61d9d916cd6e4bc185b4c196232363bdbafd8b0d28dba3624d4a9f71ed0b130da240ee6dea4265d2d99035fc5afbe89ba4eb8b228cfb104c7" },
                { "kk", "b3222983da47c93fa84d5b7cebd2b069f9f1cb8885071a4f061451672fd919835f58f31baa2b208570034a1becc9e3cf2f64158cb009a8a4daf7510f44e43924" },
                { "km", "ae6a1a1d0e2909aa6932f96789363fab60963a8fc2642ce1365e7d700cf6d0e4c2ef1a7f453de9ed34b0702b76303239bee72fff571a34805ada98f34219a9d3" },
                { "kn", "d4f909f11d1644fc66bb8b04783309d5b58a7d7b04601c3a0ec8d34b905e3cbdd74dcc1de4c54435080599fbbb32e4000c0339ea58630d4641e73c9594d1e112" },
                { "ko", "f6f9aa385fcd22be1abc0d7263e4b309d11920e12268389d7f4aa151fe881bcb7bd88adcab7fc9c60e132781772e037ece22e5f7b16847dafb909f64e95b5176" },
                { "lij", "6538f58862e709d44dcf093b76bdbddc8abab4bb3e60ea1cb2bf83d344074d020cbdbaae2d130edbdf5d24743b19ff49560e46ab284a8ab0cc715e75b79bfaab" },
                { "lt", "bf71081567990e78c5cf3605e94bb1e8046b994ca8b997da72b43fa132d70a77b9895ef0f265a2d4d067281d2d22fd1c4c72982a8948c61093de34b715593b10" },
                { "lv", "1e85b87965f84d0bf0ec677a49fe450e12770ce67e3789165b4443c5f96d627d518d92e23ab606fb65d3f163dde57bd762de1f2db617253dc63d27099ffadc53" },
                { "mk", "07fbf59e863f419b1d081c6758f7d20b230f5a48390812f211c0cceb9099f802f30704910df87d7647b7c50e9369e72aa3058061773173e4b8900226b95f969c" },
                { "mr", "008dfd7f42466af3d72e5b08653a86a0979079ae1e50c49029c11c1c22dfe7f09db1fa1066fc587f9d0560ce7e3b670c387be1575a76ab0eb18a4f9641f5795c" },
                { "ms", "ceb8895205321e3148ca8e2b11e603b6dbe7848eaf9c52fa56a7c8972fa9298812bf65f643370358800f809b53560cdc438f98363f7d33a080e5e090c58f80c9" },
                { "my", "d646f0ad0c440082ee804920914c3b227c681eb8ad4f1b4a148125d8637c5b29e6df8f82db8c8d21b670faae4032fabdf6520f6b87918aad8c9f880ba23b6667" },
                { "nb-NO", "d3f49b80b2f5e39513c45a1c5f33c1fd50a13b6ef71b24b4cf78e82b5ef21a365def5f6ab683c851e2ee8b34650251fdc8757a19f88a8d269179e354cc58272f" },
                { "ne-NP", "d1a5b0b9d9ed209bc1672358048e679c194b50181d5104562b2de9164c078f8bef983cf7109e0d754bc424f330e2ca840429e97829969998136a8fa0d71536c6" },
                { "nl", "8b766a8fbeecc7fcc9fc3a55efc7645007f0b6e1443da885d06fa58592c6810c0aeb1d0feeefe8254eee74499acecaa27a4f162cd331ba7507a98bfbf455302a" },
                { "nn-NO", "c05f3d2e89e99be27ea3dae01a3a11ab3f1cb67fc202d6b3751a1b56c5d9207e1dfdad42499449a5d3e8ae1d921d4b5ff32e031cad625e06dfe93db4eaeeabe8" },
                { "oc", "1d6af0d1f9ff276de9bd5efcfbc1c3a87ed54d0555d48f3722dd745e50af2780edce701d82eb1976caad76b6284bb6bde222e1e9deb8b910202f4b5b0808ae89" },
                { "pa-IN", "f222ac84253edf4ddff025308fc7510c08a06bae5db322fb5488412bda4e1336d4473ed79314edccd99200cb58449f4b02355f745cbff7ce5e2499e945a81de4" },
                { "pl", "333e37f3a86bd6d807af13262f317515fe663f089b885a227ebbf2e7989c063d963558fb15a7bbb5b02e6d008901d5455c2b0c1476c11eec92202e063f641469" },
                { "pt-BR", "c4b247e9b189ae747a1b2c8a23a4d8a37eb60487f347d3831afea066b6f843fb28a0d94793a67684f7b1786efa9bc29e563a9d7b30691bb6e77b0fee09139895" },
                { "pt-PT", "4901f069bda63337e8947abe77705c22311a3cd60bacee53ab30b553f4be6c12e2f2b8fdc3ad70fb141c21817290e8ea7455a1b3c368114491cb5887882ed0a2" },
                { "rm", "ec4a8a1bc2bcfd685074d3b9bb90c26823eb9fbb86dd9b450aab1f5967ae1c5c0313f02e03da4aef668630fc01f46b05ffa053a9067f4930dd9b574cab67253c" },
                { "ro", "2381b822d7f90d6821b48b9422476c9a75b0f018ee30df7c9e1647c7a9d761a72cf01dcf5887f0cd0f484314e011c30531357cc4d01846699ff9bbed1df2542c" },
                { "ru", "033fe500801783e8fc8c9000a1712e1d9e9f9d4d0cd2e670e78d0ee68e5c8806034b279b3a1f3151a622238a2c40211d2088bf1c7183233502865150debff7ff" },
                { "sat", "6f2dc855d6a4deb37202e08f637e18c64a75d189bbee0d9769e3d1c258ac8ca8473e397a7866bf82663478ad78c0cd7a2ab37252c474c27646808a237141150d" },
                { "sc", "0a9015b8b37df20e772e7c3c4cc8344b1a07105e60540f7105d80191db0924eee1c38bed88ce66bab46af584ba2da10776123f3711355557c032a66e092790b1" },
                { "sco", "b1d0eef24eda8b3c85c707a7ba57b0efad5084ab7db3cbbdb1feb8b23c2a20d3ff86a7f80669dd8c8a8e81da570d0d59231463d823548c9bfe6dcae62d2cbef6" },
                { "si", "8898da1f99e5bf48eee0bfb38bce17b979a18b82088a788def70b08ba36c27e38d786c7342548d05947a9b40b5f57e19ae66d351ab132ac668af71ebc3e525fe" },
                { "sk", "bff9f75ecbe6277cdab91ea58764dff8fd3997ba75c5870bf292ac463486f88e8961459718b0e96c8a12da4506d26333ee7c22ae6195a98ed90053601de7476f" },
                { "skr", "66eef8d07b7dd12afe9bea102e5f2fe0ea2e8f957b3c7c90720841573b7fcc205fe4f12991c5fb0c9a726ed93d24de8a15833013be308f586c33d1b5a83f2bd5" },
                { "sl", "a035a72d086883d06c298ad5175090c6aabf200f928885b687b91ff772d419dd1557c4190fc706da2a500a5f4c32a2fa41111079e956e818e57f5d6d92feb3f6" },
                { "son", "42b40b6093522cdc9d68f4d3ef37fcbd05671d7c3c16ef6a6578be23862f85965e7e73d8b74ef98bb34e8f51f948ce013df7bc2557882b2be95962aa3e5aa04d" },
                { "sq", "cb062c19ed983a406736ce0b288760340ebd0a788ffcc9d8a04fc48417c4be4513412810fdececa26755226f5b116fadb9e7626664fa536e5b5c420774cc69c2" },
                { "sr", "63c6436bef7ad68d8671ef7d09b3dae715135212ffde4e0449f7589a7854b55022db63d4516302cef14ec0b4a58b4e5d062ad03b8b9b85019c63995d3684d121" },
                { "sv-SE", "48096be567d6381626e997d3cea7ea06bd1263f0366689111e225fececb20e77870c65bb9c73e4ca22e7f6c04f769a6a866a2a75b4af70411382dc69f09c40d8" },
                { "szl", "8e7eb9c4cb34abef63542f25c0aff8d1904d9c4867dfd9b5a90b472afe432971544930661db2b38c6e98ffaffe5b05f07208bf8cfd57ef48e32d614675989571" },
                { "ta", "85a0d0a2b7213beca4f4954a918b0b88e0940abb893d0ec1b65fc736ca62bb1d2d8c19c64136f428e13515f2397418bbecc93706d664cba8f8fd5403faefabd2" },
                { "te", "1b1e22ccb054e6cf86c4c8afe6ac6e9a1256fe9b69434f721c5613f3cc2e0a759b8de6bf1088bd759cdc6dab2e6251324cb4b9f89482ee3f66bea922e6677558" },
                { "tg", "38cdf5ee2bdfaa8514cf76dc3d62fa7a27425810e529b498b461d0958d4c93aa25190bf73d8285a07ac93f9778b980759dd2c1ae988315217533c1dc070a3bf3" },
                { "th", "885a7a345a4c6cc7d3a12b825986cccaa06c1dd5ba93ac562a4b104754bd460d001c0f5ef67e72e6a5616ddc2479f4d830127dfc8c825e0715e6aeca767ae284" },
                { "tl", "ed4f1d7fccbe75de0cf5c5971dd4ac4458e4c7e2866b347708c118576eb0d9adf240ed0b506f40c3b46b2757a45a196acbf4bcdf0901d7868fc6a25bea73bc4d" },
                { "tr", "9a8ad6f59c68298b1ecfbe1a70f0cf3d47ea1c7ad40649cb9fb8d957d40d2cd0884e93504c9056825d197932a1bb048307d8df8634acb943ef5f27b024e8a3fa" },
                { "trs", "85f138afa8510607bf546a7fe4fec93a738ae376c4eefc602d245de30303950895dd51d54870e8f5d83330fdafb53a17f16b4444bc59c38c9f6a0e24420de90f" },
                { "uk", "9fea1418e6938705ed29e578b3dbd7f1ae9908223346be238ccd27af5363deea337d6604081558835ccdea5e76bbbc5bab2875e2065714296e75f4f6f5030366" },
                { "ur", "312c78a5974266d6b4107d13da41e83f36a9aca6e2a111e7538ca2cf9bb88ebf939a961e07538e150a648ab622fab59edf281023840d37d51068e3bc130f1846" },
                { "uz", "02c53447128babd1125d1a9826eddef14b621a5e1716e8e8bd1d42c00d889ec31f757b3e40c9d43c1d0064dc43f6dab68a9efe2c47ac60f54baa88064c153e02" },
                { "vi", "daa184d2b4fa861dee61afc17d07906c25db497ba22789ac2088e81e8fdfda6e6a112af8ccfd97faeabcc91c6da5911e6468df7f10c0de21767c861e8182fe04" },
                { "xh", "da8c9b1663384f77297561dddab6dbca18ca61276e108306b858ab173233b56e98eb50e0d7259554b2c7954a97327727f46a07a80374e083ee86b542d4860757" },
                { "zh-CN", "505bcee2a320530cd33e3547986fac996b119ef573b30cfbcef8ad0d6ecfb13b3f41ee73883b568be34a1eba6cbdb715e8e77a53d635bb5606b1da99f028ace6" },
                { "zh-TW", "96951471866a6619a24f2249403a81e0fe462cea4d7f391fac2c69c7e803e82a651dfe7858a1633747abdc36bd0faf4d4260d15fd7e7332aa90d468ee72ef59b" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/140.6.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "bc3d7f57a7a47cd55d07eaa47786fa829145c8a345d13d75bf72a0bc24b4527ee7ee65eafb03109159b12baddee70e34a8294f6200d29f6b8698fbfb3ab9b16b" },
                { "af", "51ee6dc3d471f1334f152d8bb0dd1d89371dc6a302146f13847bdae99f594041a741c393fb3fe318a5b8439d786504603cd6a7a4ca219d93182b176a0ae31814" },
                { "an", "6ebc4a547a3e9631483fdcb889355854989186d4fc4464216c4f6942df4ee832e45d8c73e5561674c58ed381f1dd21a0f125fe8a95ae610ea5b957bae09cb53f" },
                { "ar", "24b07ae93300b694904673b2dfa717f94f4d12c879f5b69b08ff52b2833b8ffa7f4fc89be72c9e81b45ca3b87c50e10852a20dfc1eab06d621cf9c79ebe644e3" },
                { "ast", "d5ac1c89ceb685ce8f2d1b78021fe6df2de9a82d999adfdee76c958e05d55e06d6e0362c6bc35ece3f921c6d3110983a45c0636d7811848458ad352e1c75d210" },
                { "az", "dc313eed810933b43ef1ea17ec189e5cb7a67c107941337a1b800abf89a7042ed7e79381032179362a936c863ca6dd7d1f963faa18df0ddff1dc3816274f1fe7" },
                { "be", "9fcf7a57d2e697c04d57c915ea41611beaced71de99e8ceeb49a0fbfb14d31d4143719d09a3c73257bac6364dceacd2f563d57837ef18828adfa2d693345e9a8" },
                { "bg", "70a18c746609fdc4064f17b2f7554afffb3be66f1b8d02979829f80763aac6df86d48d4c4c1ec1d25f738fe4686b2cc034692880394a11a46ca52f2801e23e56" },
                { "bn", "33dd277566ddf0bb92ede1b875a4d308c35404bbe73efb5b63521cb152597e5a12a0050a1036843f28f87c9a5172b0bfba2a9a09aef1396b486a861b0312bf2e" },
                { "br", "565f75db9cf797f5661d40ba0412a5287ef606ed4c4ae424c40230507a14d42f7dff22182d3ccb40d1bdc162907dc028c809276a6eacb9ec0a58425d5c63727a" },
                { "bs", "b57982884407a0a07f5246704ce00bfa51025a38c76c60b5ed172b35b429ca7c57470e5e08a6ec21903414c9445008b93d89e5433a7c2acf4574acfeb1f96717" },
                { "ca", "16aec9ca12e8877fa30eb22c116efa8da0c82fac218a4fbb124a0c1054e9b8309d85ba6077100f03b03d7bb0e2e6766365ab35f4be144c23280ef18bd4f5993b" },
                { "cak", "b2407561b8a5c860f07eafa726ae5856c3f532e36add3ff46fe68a9e999ea7cdc4b81608751a97723a4998daf61c619c4e72bade54208cee43c09db909838b34" },
                { "cs", "18849a699b85f35b95b28ca4583ecc8e02b1abd702dc347187624e77166dd1c3aa7146e336b33c528b5f25ac9ed189528cec2257ffa26e4a1248bae031b25f69" },
                { "cy", "25dc6558a09c86d6e443d8d522543488551796f246cbca15ffab2e4b5aa36438674dd015c647f5eb29771d6964631202abde6476a5eb40c2a05e2a55609431e8" },
                { "da", "9451ebb47cb527eab58ed2cdc7683246164b607ac58f31877c9753ba2b979ad2cebc67910a8c9e550bdeda0eefeea4a0103f4d11025184b33343db19154fa6ca" },
                { "de", "2f33315be01b5e577e8b3ec488de5df342093a19cc59b6c50dff63390f88a2e1454bdc66e1dc23fad0d873c7b6e19249300ae1c4c3604d8bc087c9c3f256d66f" },
                { "dsb", "0437cf6431b2d014e88f735db7da7f8aedb3a7f73882e6e7cc6556a55d0858c207f611b134a29c6b2dbe289ea4eb66896d4630236619e197efa0d3240b497c12" },
                { "el", "e0ff2f77305c64bd546ae5b78eda0ab631a68c51fb3f0a6dec4e9bb4e1ee1a5910ed6b5077c870f384fc93ff62b644c5b4998803e90485e3901098625b01388c" },
                { "en-CA", "f81b8c31970a99d6f1f9284d823b7487e78482b5a51e55804bb0f567635b96834a9674884339e652019fabd9d9c4208425b997d4fb8e013941e43f1b4cda9447" },
                { "en-GB", "bb78d17261aecbfda829a9ced5e1795f55a54a0af7c91fdb8d3650388dca843ca362d32aee814e5e2cd7a929a0105ef0267547eb04a2ecaba1d9f81eb2a5a83d" },
                { "en-US", "a2c1e24fa376c295d79879575c4883aa3e291050bd7a6b409bd788f51c98c87e2d792663de98a6bb734cf7d351467bdccdf2af04c3f0da1519dd6a0baaec346f" },
                { "eo", "cca08d3fe450333f731a100514375fbd226840bbbf74f4806f5be9041e215b75818460498151a741f81336ab3f6b22304571b245d0203ab56f1c31742e2b2914" },
                { "es-AR", "a723707a60c51ef33807a10f1790ab568524fd7c70ca1457b96e90c75c4ed8bea8db129953b139922e153a5967d70cb35e4eaad609781529c46a182602c59e46" },
                { "es-CL", "9f251c779e4a8c9ff4808169af93e1ab637a871a3ddc71560082c7e97f126f0c2344b23a3d25094c9de0ab357c07315eb3afb0e7c01160e12326ab86311fbfc6" },
                { "es-ES", "8baaf3c17b69736cf53e979f1ce101f396f243fd801b787d3962e883d784a5da5fb159f169397c90deb4577a37dcd87a22c19f91da265f422770f24e4579dfe7" },
                { "es-MX", "34dab68ff0ff06b5148334c82cbc6d7a27b389ab0c210368b85f711f3302f127e386bdeaab1dd9cbe22377ea47c7908f94a141bb328a9c69f37d5d1902ffd1e2" },
                { "et", "a4d659f11425170cdc1a4760b21b50a12028690a5834970c05e9070776f76dd9fdc0d9edacea93ea52df7ac594c2b8985819d9d1b407f400af2e96b3e4faed74" },
                { "eu", "a3ecb921c6dd53e661bbbd4dd7bf17b04c235f9fb4582372b8219f1ab6d5924f9e0250772f4ff8411d4174afd4663bf2495e36bb79362c04dadd5c336f89833e" },
                { "fa", "98dcfbf2eab743cb895d0db9ba0e3aef9c11bb56f7d08aee1ff1a11f05a4b7dcb6875d399fb4e3afb54638cc96283eceefaf02845868172f69774d9b202d9bb5" },
                { "ff", "22645b4a7f9c094d99ea5ae4f0a89ffa9cd24a568ee103d10efbc4880d36cdf5fe38a89fd9bf7a617cc5fbb3962be68901dbcb1e6bbc78011b37779e84fb565a" },
                { "fi", "319a75c422acca23053e0d555d61d8f317798c4ab33c5a2fb04b91f5eef3882ca7a12d9b5fdccbe68c93496c54e7c76bb5b9b8fdbd1024c71a7e6645641368df" },
                { "fr", "e2d0837f94eb749cb661d382f5eb8e6333f41aa8c97345c470b2dfc846b90ad8e496d466a93e5578a47d6f49506204b04e4e0700829922fd8166f55926938f4e" },
                { "fur", "f01e8c4a98b7580f227975ad2532bc305745acb9b302d893c02e36f08925a340616cb8ac2377b3caa560a5551d12d0392829c6e0571a43a93d2914393848a07b" },
                { "fy-NL", "c566530950b4342bd8598d0bc9d3232e73dd8c9ae9171738bf6be62c8e3215eff501add8b498c3996da328a9dcda1edbcd60a9e7dc9582d6c80b142fd6ba506e" },
                { "ga-IE", "806526ca49c4606dab4091ba7eb125c5368166482b5467e534446dbfdb55a7706f0a8511881f1a490f658ef4005a6a38c66210ef4c1c1d8e7f0630b23d3f3257" },
                { "gd", "50f414ee33dcb75562119228b1234eb99daf31efa32db63a2bd9032c30c733425ed766cf3ec633437fecb882ce8bd2b9132bab58ba4894112ec20ac8a237c01b" },
                { "gl", "1a65c916f9754dc323ddb20c984b1c743de996a2ddd782c28114417735085088fc71d272b1405c7c5b3cafd0b0991604d76c16083cff0d6cb868f19324ab13e0" },
                { "gn", "642519781559b3516349b5936ce395ebbd484326e0d96af5214a2d30e7395779285b4ea6afd77f2aeb1a51de6f8d10d2c5d5f6852b45f602663ef1e5512d62af" },
                { "gu-IN", "1680eaea9c24ba12f5f79a5ab8ef5625ad4de17f01b052af781c7d68d3e0cd97bff7344b82e259c9e0a0d5de665554e2204570e3a22ea835a350f09c13df6dae" },
                { "he", "03212490603dbb0c3fa7998fef1a8bfe336c1f306a3f678604548be2162b1bf132ad1edaca30092f7521b4d60e438166cf77a0208bf224da5f0b43c36820ada5" },
                { "hi-IN", "fc221216d49d0c1f8c4a615a2f165a2b7862e48cdbc701d7d1adf262deb83a1c2d06814b6e0497283f1d3a194fc0a9f52668d6aed5dc7d87c5ab15f80d49cce4" },
                { "hr", "85a36f3913fd6f9e3f882e4aa7555fa82770b20507834b62484b8f8b0f258d1f6781c8ddf728427179147578a95a5df6b7d35105449236f82ceba415a1d304aa" },
                { "hsb", "ae2491a193bd0910a43c5b13bc4d5ee601cf5aba15f746a4155f9c0cce64e065debd433a46e3aa8524cd077fbb19d8970085691c241d08a467efd9baa9793c0c" },
                { "hu", "ee42cddaa46b96a1100a8ef6218d61966081c9896ee0edeb88d3f224de78af13be94184605cd46935275a2b8c1d8282ab30de85cd01d987472cf25efc0286f0d" },
                { "hy-AM", "4c36fdb9274760737223d6286db861b4b2d7eaaea0c02062750f621fc910aaa5444f554138120a6258d7b80d0dbc0b094dc9baed04c87b4b0639f60539078113" },
                { "ia", "1392f78fb62063b59b657a7b3ed5e478a4386ffd65d7b3298f10c26503f62aef4d3d3b6526d1f475b7622079f658f298727c295da09a23db3de83ce9656cf4d0" },
                { "id", "8c82aeb7cc2b5b1b15bf61dce52d936316f57c7e0dc483bf80ec2d179e6088ea556bad8ba22ac99de5fb5d16c35b4a79cd773a1cc3adf329583ba57d6ac295a2" },
                { "is", "a1d9a52bd278401ddcc6e2812af8dceffedc1bbb0152a0c9773aceb0650bc4a3ba25edc5829edbf4afddf33cd0df5a71bbb67605f694e831acba84979d8c36e7" },
                { "it", "37423ae13bb6fb7d2670a63704945399881e4d2811fc72c20868b1beb7098f0e44b166e268c438f9ce013545e62e924fbc651d1a6ad3a183c80a34c5badd4bbe" },
                { "ja", "53a1ae6fb8dc5d805db344fec43e21ec7427316cc3f340e72e54a61cac49aa2ff3fa545f008933e6707f5665f00085e63e5a6411dc84b98bf828fe41f5db5948" },
                { "ka", "6b3bbfb893824c498d409037943ae1feb5606043e52370b608961686dd59b9ecb2e955ecf5583c018e75fd6ca72be811f23cbedc0a7b5b0ff805fe2847d86fee" },
                { "kab", "a69e146306356ba796b4cdb61e6ed7e355d98802c11ce40c43b2aa01c54d34d6619bc70580032940252741f2921d374776b59058c58fcba718682efc1d6e747f" },
                { "kk", "f9f077277fec23541033b17484771e1e02629ac5e735c81116ad79303ecb87e485a25ed78784208eacf78eb88f113d0d143c21b18382b1944052c2dbf1ce685d" },
                { "km", "49dfdbdb1935a7df80583c1a3eca904d8769fe92885395201e2fd804c6ea544e8b88935cdcbde7199281dca0b2151135b1bf62293e102e62a34dd7060df5c836" },
                { "kn", "a70aa15ac76bae2fc1ca48404d2c0d5f7e8b9d9eec104bd70be92b54cb0a9078c934394b7e041f63c468ad0ce410ec3c8729e70947692b2b42d449d95f940d77" },
                { "ko", "c6af4992fba67327af018d7b4c3184ac6ceb0720379719c81d8052984acc1ac0fa0876a3d3d5bfed874026b3ffc52eb23b85f966bff14a1e9674f283651829c3" },
                { "lij", "a823387f17bd15d055fdef48fd253ec7281475b4324531554ed833f711a98587cd6e62fd744788da3302a93d69814e64e27209dcb69f2e3ac29a52b959c4c15f" },
                { "lt", "3995b87eb782e131d3e57f8f76d36d046f7d56ef7879d0d4abb25148dbb37db944a4be3f1a2b00211ce830a371ac29590569a603d4a02ba5f657166715fbfdac" },
                { "lv", "ad76e33cd518accbc56c3343ef319c30e3abf8f946144660a48b3536b08cd0bd1ec855ed5d09f4c0ef11002291bb0296b5249cac6ba61fabdc35d22f9837acfc" },
                { "mk", "84540eef83623d782c1ea744e60b739b9e102f4afacb77c40fbd5e76a693aa17135c897c1c2c98ed473da9a1d055df0d3e2e1d3374182b1dc155c619c496e818" },
                { "mr", "949cf9d4fcbc3602f262ed3a88416d006b88657ee8b7bf3b051cec041d7c1bdd708142b9810ecf75096265af12dd298dfc88ed85f453df519c1ed1d08a5bf3a6" },
                { "ms", "202ed6e1fe39bf27a0c12f9aebc5b109ed700b303cc6e767547d54f1f2388962bfb49f397d37a967bbbed86d9a2c239b3732cb10372c37c4504b9a520ffafa13" },
                { "my", "3b22d4261e0fa8fdf9ae1b5a9718454ffd2a664fe7cc46a1265c84a180c7e4e1de6ba917cea5d54348c88538a54d0873c9f019d89e7658e1c88a4342e955bce8" },
                { "nb-NO", "838e0080a4cedbe70f85716d5d0c25cf2d48f9072cbb0e83bed4eab68b1d0b6a26cb6db6ca507d4dd695c678afcfae1dd00f6af9bfa895c1aa90256ed47e9a23" },
                { "ne-NP", "df3095fbb5620ad41eb8db61cfdff462e8949862dd0d900310ee7a85faa147b19ceb14c220ba0e4e676ceca4ad14bf1d254820aba52bea6eeaadbebe5b3bc911" },
                { "nl", "bd433494d38c263f936eae613dff7c034e7bbab8c1e4cbfc662244a152a23bf5ace40eeafbd8893e94c6e7b03ed9d5fa88048942345f718e29dd34bf75ac71c8" },
                { "nn-NO", "652c3f98de071ed415334bd15c6b4013c7ea381f620cc390eaee5140c9d247c7f3e53047cbb4f3ccbb03cbcd56f1594524da63bcb0631aa8f0c73f177aa3a602" },
                { "oc", "7d747223f1d8182766b031940795b09d0fda3bf4b22c760c313f2b0b7ddd1ba7a869a16a120f58c35ddc30c58bfadd90e10edb9d6d6e6a68b34bd5f7b8d8d239" },
                { "pa-IN", "ea23336a53f815bd8f7fd60440176771b07a3e7cc9e1a097a9aa47fdac044b3f806d0116c22c14cec7522dc9073a94dc0eeea4ad6aee03a9e3d412f4abbacb12" },
                { "pl", "69fc92a73e2d03d1c3fbbc960cb0ac969b7e0b1066feb878020fcba16343a1f9292fbf31bb3ed441fa98daf4acfc8415271f276434d4bd10e3d8fbfc8b9c16e0" },
                { "pt-BR", "fd3ee2c48424cd1b6bbb55493f73228de5a7da8a0e8e64c6b7d4175bb282b93c4aa020eee8274c0d9b093a248cc3729e5f2b4839d5074d4bb3f745f7e4b79943" },
                { "pt-PT", "e8f181b3f20bfaf499ae13c0f1f34ccfb7b8a2a8352ae965e6c9ee2cbf1fad7ec8cc60f8dca2e6edd502d9baf75ab189bf1e574997a4ac64139fee4b2005e25d" },
                { "rm", "4c9b913c9ad89635240be6f6f639cf2ae0cf5a694efe9740699eb96b910be5cfd4390a13323e8bfeea7578216955cd0dd7f204fbd096713fc0bb178222bb4456" },
                { "ro", "a8c0d201e7aea24473f3dfbb0f94ac388bb2ef3a9f178fa3e7bdf8fcbb345f0d00d150fc8456db3d8191dc9cb20b9249bb4b3d7a0bc2689f85d79687d8cf9ff6" },
                { "ru", "0edab827169dd29eed1dbd3a252a3e2ec4f8dd666eb71d2e361947de8512db1f3f4cd4c7ac9b7c4948e8a8cf5ff60f47401653130fa850ce8fd0e49ca875d641" },
                { "sat", "46563811ead7b4477cc0bbcea85a6b14ce7048b035ba616020e1c6976381c02acfa090790b6be98c9e5e72bbdd3bdea286a2a8d9b0c866a7938e266cb7a823f5" },
                { "sc", "f18abf351ed363a8b33d9448c2323d6dcb61df5da4366bf403d1eddf5415669e70157cae2ba16e2b0de7a06b0c03e9bde79d9646e4609fc950c24c0b172b24f3" },
                { "sco", "2ee8e1914121d80589d8d42e28552094920ea528099b6e5dbf3a3ac964ba34758ada3ddc6728fd4bb12ff29618592973613430219dd90b07e864a0c8f1fc28b9" },
                { "si", "2f9809de9b48f0001acb12dc89db8b8cf8dab87a029acc3f3fe401283bd34c5af24807cb05726b73132409ab687a4d0391ce151dc225f316df92f052695f1e93" },
                { "sk", "4b7ce4fcc5473351d0922b0f5b4a993e1e1f62f5f587e79bb881f8e8802f6c1fe01830d20432116f20ad693074a8d0918df9916a48e9386feed5a72508d6fcd7" },
                { "skr", "c82d928a0024d1d6c795af5eae3e4b20bc721f13c3e396ee66255865471d8775be4bdefb1042f8b67460bc7d6122c6e9cfe21a6ce1d6b8068551f33f09504f80" },
                { "sl", "a4ba45345920253b5d538e474c8f9ade4d2595057dbc50c885f8b35b8b079ccb66d1826c48ec313cd8dff47ee148bd68b4e2a38313b7d63e5d32f04a3dccd7b6" },
                { "son", "7d40653940fcf44c71b95d4a6de6d887d12c966a39f895ff9a824e5f21e798c3938b73ac5113e3bfca39521d2f2a6a5d6bc4a9a83f44c573daca3b23989b02bb" },
                { "sq", "0149162bf4a34b3189aa610fd9e89b971d0953aebe43fec30a54768917802a91a7cb9dd00a2417e665b023aac0ed308881f42274d46dab4628e19a183e31f8fd" },
                { "sr", "6e0c744a820045afa2c420044941be345a20da0ad4f19cb4649749a44c752381fc6696e087c79b6c353746ac4724d721cd6d904fbb25f573bf2c1267f9276805" },
                { "sv-SE", "dc42fa2819f6a0d9306d2e9d564d0677058bf58fd90b4dd3f7a4eddde5faccf51c8adfe8388924a5f567d60dfe4075869fe789f0dee9fdb9840fe4c53f1f94f5" },
                { "szl", "ca0e957d3b4eebac4b821363b6ee8d470c2fbb872b87a940a0511c98c04aa569614044455c422b96025bdc45385cbad1b5a3f746dc15c6149ae5a209d6e6c244" },
                { "ta", "f8821f0e2eac5bc82b8a406a43245a6ea23da897e488d5c9a80618cbc6b77f9e55bc70dd8e253118c6f64ae2e62735d555c0cbf7050fc18392879d7ec28cea07" },
                { "te", "4b65b12cbdbb34853f157a4c5cf2cb3e88f3c787905e53fc6a25171a3606779eae3a2920b9efcbcb33d22738cb6cc494b1349dbfdff13e5e32105fd5e42240af" },
                { "tg", "b182c01a14f3920da142da0bc621bc14e0743c76107ec6c7bf1d2b0462ce34ca41ff0b807a8f1dd82231649fc92c386d9c3017d21f72063b6fe8643702f6bf74" },
                { "th", "322cbc8dfb745ad9b9974a8f3c9acf2fe19aa7d645713c83d24c24f53e8bf78d55cfebf1478d3a2814c8046d16560f3b5868dddb03b0d0c10300768476b7f77e" },
                { "tl", "f0cd839a09cd903d0adf3422188260191eec9a15b5007c832e1a1ba261e70da38349211c13dafb3b1b507fd80cc22c4cf1faf7e81a9404fa8f6bfbd3d38bad5c" },
                { "tr", "3ed94929270eac6d64f8c5f863659f744a2756cc55b9daeb4edb0c1879c56e29bee55252006c7ca452db567cfed16c010dbe9a48faa7722a6d55fb54c3843e00" },
                { "trs", "64bbf354896d8f134759d1ab930150d869b8daa63ce04cb15dcaab162d6e1c4261243cee7271ccec86761cb6353eafe8e23ef598d380bdf847b33999c8ad8a48" },
                { "uk", "fe2dfcb7f3798283aec40f5c7d7c447e7b783ca6401970e5898993d201597a968b03eda930e447f752b0192b43617783e0c965ff674121cce724b562055f3be2" },
                { "ur", "f07981a2049d72d35099232be5e94c79ebf85d0d5635e15ea5e295741e2c6f97dfdc6849cb215b6920ba801b7bc72add8034bfb74937c0e4803e97df402b9fef" },
                { "uz", "6929abfcad58f99951de21e2c01152774b685f07551f7cf5878ece7d923c9a824eb266a0fa8d2cb7bfd458789d17275e20bc8720ddc46abf99480416bbb7897d" },
                { "vi", "69793752bf118ea204fe0d18436eeb3064d1f6e7b050bab7007b428e6f991ee0be840bc117918ece3fc71941d9b79581e847e4f9a713fdc1ef3fbb5eb82ba23e" },
                { "xh", "8cac180ebac063240cd2fd6beeda36b0243d23173bd2a5707997103a66ad356bc4429db18eb40255db751339c9e4a9c3b83ea4271d096502e05f51e0e6a1e0d6" },
                { "zh-CN", "47906f0b333098759d99948b78a0f97bf3fac60a8672dc5d25cfc982c9bff02dc9d5a48ae004d2f8b1dcc256265047f3a60104cf5bff2770e7789c300c04a363" },
                { "zh-TW", "5509162b420dea12e8cc36075c765e2b1dfc3852191c0922c076f72688e4ef30a2bd2f4ea63b58e5f3e3dd0bf6923c3ded11f056093e1c4b89e1f75e507dbea9" }
            };
        }


        /// <summary>
        /// Gets an enumerable collection of valid language codes.
        /// </summary>
        /// <returns>Returns an enumerable collection of valid language codes.</returns>
        public static IEnumerable<string> validLanguageCodes()
        {
            var d = knownChecksums32Bit();
            return d.Keys;
        }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win64/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
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
            return ["firefox-esr", "firefox-esr-" + languageCode.ToLower()];
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox ESR.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=firefox-esr-latest&os=win&lang=" + languageCode;
            var handler = new HttpClientHandler()
            {
                AllowAutoRedirect = false
            };
            var client = new HttpClient(handler)
            {
                Timeout = TimeSpan.FromSeconds(30)
            };
            try
            {
                var task = client.SendAsync(new HttpRequestMessage(HttpMethod.Head, url));
                task.Wait();
                var response = task.Result;
                if (response.StatusCode != HttpStatusCode.Found)
                    return null;
                string newLocation = response.Headers.Location?.ToString();
                client = null;
                response = null;
                var reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                Triple current = new(matchVersion.Value);
                Triple known = new(knownVersion);
                if (known > current)
                {
                    return knownVersion;
                }
                return matchVersion.Value;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox ESR version: " + ex.Message);
                return null;
            }
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
             * https://ftp.mozilla.org/pub/firefox/releases/45.7.0esr/SHA512SUMS
             * Common lines look like
             * "a59849ff...6761  win32/en-GB/Firefox Setup 45.7.0esr.exe"
             */

            string url = "https://ftp.mozilla.org/pub/firefox/releases/" + newerVersion + "esr/SHA512SUMS";
            string sha512SumsContent;
            var client = HttpClientProvider.Provide();
            try
            {
                var task = client.GetStringAsync(url);
                task.Wait();
                sha512SumsContent = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Exception occurred while checking for newer version of Firefox ESR: " + ex.Message);
                return null;
            }
            // look for line with the correct language code and version for 32-bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64-bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksum is the first 128 characters of the match.
            return [matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128]];
        }


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be updated while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            // Firefox ESR can be updated, even while it is running, so there
            // is no need to list firefox.exe here.
            return [];
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
            logger.Info("Searching for newer version of Firefox ESR (" + languageCode + ")...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            // If versions match, we can return the current information.
            var currentInfo = knownInfo();
            var newTriple = new versions.Triple(newerVersion);
            var currentTriple = new versions.Triple(currentInfo.newestVersion);
            if (newerVersion == currentInfo.newestVersion || newTriple < currentTriple)
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
        /// language code for the Firefox ESR version
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
    } // class
} // namespace

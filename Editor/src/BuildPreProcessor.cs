using System.IO;
using UnityEditor;
using UnityEditor.Build;
using UnityEditor.Build.Reporting;
using UnityEngine;

public class BuildPreProcessor : IPreprocessBuildWithReport
{
    private const string PackagesFolderPath = "Packages/io.getready.rgn.signin.facebook";
    private const string DestinationLinkPath = "Assets/ReadyGamesNetwork/Linker/RGNSignInFacebook";
    private const string LinkFile = "link.xml";
    
    public int callbackOrder => 0;

    public void OnPreprocessBuild(BuildReport report)
    {
        Debug.Log("[RGNSignInFacebook] Build PreProcessor");
        CreateFoldersIfNotExists();
        AssetDatabase.CopyAsset(Path.Combine(PackagesFolderPath, LinkFile), Path.Combine(DestinationLinkPath, LinkFile));
    }

    private void CreateFoldersIfNotExists()
    {
        string[] pathParts = DestinationLinkPath.Split('/');
        string parentPath = string.Empty;
        
        for (int i = 1; i < pathParts.Length; i++)
        {
            parentPath += pathParts[i - 1];
            
            string currentPath = parentPath + "/" + pathParts[i];
            string currentFolder = pathParts[i];
            
            if (!AssetDatabase.IsValidFolder(currentPath))
            {
                AssetDatabase.CreateFolder(parentPath, currentFolder);
            }

            parentPath += "/";
        }
    }
}

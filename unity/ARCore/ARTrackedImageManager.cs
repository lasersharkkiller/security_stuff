using System.Collections;
using System.Collections.Generic;
using UnityEngine;
using UnityEngine.XR.ARFoundation;

//Instantiate separate prefabs per image target, remember to assign prefabs after add this as a component
public class ARTrackedMultiple : MonoBehaviour
{
    public GameObject prefab1;
    public GameObject prefab2;

    // Start is called before the first frame update
    void Start()
    {
        GetComponent<ARTrackedImageManager>().trackedImagesChanged += OnTrackedImagesChanged;
    }

    void OnTrackedImagesChanged(ARTrackedImagesChangedEventArgs eventArgs)
    {
        foreach (var trackedImage in eventArgs.added)
        {
            switch (trackedImage.referenceImage.name)
            {
                case "flareon":
                    Instantiate(prefab1, trackedImage.transform);
                    break;
                case "mawile":
                    Instantiate(prefab2, trackedImage.transform);
                    break;
                    // note the target manager supports up to 20
            }
        }
    }
}

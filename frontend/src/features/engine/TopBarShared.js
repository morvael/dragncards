import React from "react";
import { useGameDefinition } from "./functions/useGameDefinition";
import { TopBarSharedCounter } from "./TopBarSharedCounter";

export const TopBarShared = React.memo(() => {
  const gameDef = useGameDefinition();

  return(
    <div className="float-left h-full bg-gray-600" style={{fontSize: "1.7vh", width: "16%", borderLeft: "1px solid lightgrey"}}>
      {gameDef?.topBarCounters?.shared.map((menuItem, index) => {
        return(
        <div key={index} className="float-left h-full" style={{width: `${100/gameDef?.topBarCounters?.shared?.length}%`}}>
          <TopBarSharedCounter 
            gameProperty={menuItem.gameProperty} 
            imageUrl={menuItem.imageUrl} 
            name={menuItem.name}/>
        </div>
        )
      })}
    </div>
  )
})